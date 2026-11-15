// Proof Gatekeeper agent — HTTP server.
//
// POST /agent accepts signed task envelopes from the Agent Games platform:
//   - {"type": "agent-games.preflight.v1", ...}
//       -> {"ok": true, "protocolVersion": "v1"} (signed)
//   - {"type": "agent-games.proof-gatekeeper.v1", "task_id", "mode",
//      "issued_at", "deadline_at", "input": {...}}
//       -> {"decision", "reason_code", "proof", "public_signals",
//           "proof_tx"} (signed; proof/public_signals omitted only for
//           PROOF_REUSED tasks and when proof generation fails)
//
// GET / and GET /health answer 200 (health checks); GET /agent answers 200
// so a health check against the registered handler path also passes.
//
// Security: every inbound POST is HMAC-verified against the RAW body before
// parsing (x-agent-games-signature). Every response is signed the same way.
// Fail closed: any error or uncertainty -> REJECT, never APPROVE by default.
// A correct decision without a proof still scores (+12 −2); a wrong
// APPROVE costs −6, so the decision logic leans REJECT (see src/decide.js).
import http from 'node:http';
import { decide, REASONS } from './decide.js';
import { encodeTaskInputs } from './field.js';
import { generateProof } from './prove.js';
import { signResponse, verifySignature } from './hmac.js';
import {
  getResponse,
  hasResponse,
  isProofSeen,
  markProofSeen,
  saveResponse,
  stats,
} from './store.js';
import { checkProofOnChain, warmChain } from './onchain.js';

const PORT = Number(process.env.PORT ?? 8788);
const HOST = process.env.HOST ?? '127.0.0.1';
const HMAC_SECRET = process.env.AGENT_GAMES_HMAC_SECRET ?? '';
const MAX_BODY = 1024 * 1024;

if (!HMAC_SECRET) {
  console.warn(
    '[warn] AGENT_GAMES_HMAC_SECRET is not set — running in DEV mode, ' +
      'accepting unsigned requests. Set the secret from the dashboard ' +
      '(Rotate Secret) before registering the endpoint.',
  );
}

function log(...args) {
  console.log(new Date().toISOString(), ...args);
}

function sendJson(res, status, obj, { sign = true } = {}) {
  const body = JSON.stringify(obj);
  const headers = { 'Content-Type': 'application/json' };
  if (sign && HMAC_SECRET) {
    const sig = signResponse(HMAC_SECRET, body);
    if (sig) headers['x-agent-games-signature'] = sig;
  }
  res.writeHead(status, headers);
  res.end(body);
  return body;
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_BODY) {
        reject(new Error('body too large'));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

async function handleTask(envelope) {
  const started = Date.now();
  const taskId = envelope.task_id;
  const mode = envelope.mode ?? 'competition';
  const input = envelope.input ?? {};
  const proofTx = typeof input.proof_tx === 'string' ? input.proof_tx : null;

  // Idempotency: a retry of a task we already answered gets the same body.
  if (typeof taskId === 'string' && hasResponse(taskId)) {
    return { body: getResponse(taskId), cached: true, ms: Date.now() - started };
  }

  // Reuse check (synchronous, before any await — atomic in Node).
  // A retry of the same task_id is NOT reuse (store.js keys proof_tx by
  // the first task_id that carried it).
  const reused = proofTx ? isProofSeen(proofTx, taskId) : false;
  if (proofTx) markProofSeen(proofTx, taskId);

  const { decision, reason_code, checks } = decide(input, reused);

  // Best-effort on-chain confirmation (log-only, never affects the decision).
  const onchainP = checkProofOnChain({ proofTx, proofVk: input.proof_vk });

  let proof = null;
  let publicSignals = null;
  let proofMs = null;
  const deadlineMs = Date.parse(envelope.deadline_at ?? '') || 0;
  const timeLeftMs = deadlineMs ? deadlineMs - Date.now() : 60000;

  if (reason_code !== REASONS.REUSED && timeLeftMs > 5000) {
    // Generate the decision proof (the circuit enforces decision correctness,
    // so this can only fail on an internal error — then we still answer with
    // the correct decision but no proof: +10 instead of +12).
    try {
      // task_id lives at the envelope level, not inside input — merge it in
      // for the circuit encoding (the circuit's taskId public signal).
      const enc = encodeTaskInputs({ ...input, task_id: taskId }, decision === 'APPROVE');
      if (enc.error) {
        log(`[task ${taskId}] encode error: ${enc.error} — answering without proof`);
      } else {
        const gen = await generateProof(enc.inputs);
        proof = gen.proof;
        publicSignals = gen.publicSignals;
        proofMs = gen.ms;
      }
    } catch (err) {
      log(`[task ${taskId}] proof generation failed: ${err?.message ?? err} — answering without proof`);
    }
  } else if (reason_code === REASONS.REUSED) {
    log(`[task ${taskId}] PROOF_REUSED — no proof to submit (platform excludes these from the bonus)`);
  } else {
    log(`[task ${taskId}] only ${timeLeftMs}ms left — answering without proof`);
  }

  const onchain = await onchainP;
  const response = { decision, reason_code };
  if (proof && publicSignals) {
    response.proof = proof;
    response.public_signals = publicSignals;
  }
  if (proofTx) response.proof_tx = proofTx;

  const ms = Date.now() - started;
  log(
    `[task ${taskId}] mode=${mode} decision=${decision} reason=${reason_code} ` +
      `proof=${proof ? 'yes' : 'no'}${proofMs !== null ? ` (${proofMs}ms)` : ''} ` +
      `onchain=${onchain.status} (${onchain.detail}) total=${ms}ms checks=${JSON.stringify(checks)}`,
  );

  if (typeof taskId === 'string') saveResponse(taskId, JSON.stringify(response));
  return { body: JSON.stringify(response), cached: false, ms };
}

async function handlePost(req, res) {
  let raw;
  try {
    raw = await readBody(req);
  } catch (err) {
    return sendJson(res, 413, { error: String(err?.message ?? err) }, { sign: false });
  }

  // HMAC verification against the RAW body, before parsing.
  if (HMAC_SECRET) {
    const sig = req.headers['x-agent-games-signature'];
    if (!verifySignature(HMAC_SECRET, raw, sig)) {
      log('[auth] rejected request with bad/missing x-agent-games-signature');
      return sendJson(res, 401, { error: 'bad signature' });
    }
  }

  let envelope;
  try {
    envelope = JSON.parse(raw.toString('utf8'));
  } catch {
    return sendJson(res, 400, { error: 'invalid JSON' });
  }
  if (!envelope || typeof envelope !== 'object') {
    return sendJson(res, 400, { error: 'envelope must be an object' });
  }

  // Preflight handshake.
  if (envelope.type === 'agent-games.preflight.v1') {
    log(`[preflight] agent_id=${envelope.agent_id ?? '?'} nonce=${envelope.nonce ?? '?'}`);
    return sendJson(res, 200, { ok: true, protocolVersion: 'v1' });
  }

  if (envelope.type !== 'agent-games.proof-gatekeeper.v1') {
    return sendJson(res, 400, { error: `unknown type: ${envelope.type}` });
  }
  if (typeof envelope.task_id !== 'string' || !envelope.input || typeof envelope.input !== 'object') {
    return sendJson(res, 400, { error: 'task requires task_id and input' });
  }

  try {
    const { body, cached } = await handleTask(envelope);
    const headers = { 'Content-Type': 'application/json' };
    if (HMAC_SECRET) {
      const sig = signResponse(HMAC_SECRET, body);
      if (sig) headers['x-agent-games-signature'] = sig;
    }
    res.writeHead(200, headers);
    res.end(body);
    if (cached) log(`[task ${envelope.task_id}] served cached response (retry)`);
  } catch (err) {
    // Fail closed: never leave the platform hanging — answer REJECT.
    log(`[task ${envelope.task_id}] internal error: ${err?.message ?? err} — failing closed`);
    sendJson(res, 200, {
      decision: 'REJECT',
      reason_code: REASONS.THRESHOLD,
      ...(envelope.input?.proof_tx ? { proof_tx: envelope.input.proof_tx } : {}),
    });
  }
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);
  if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/health' || url.pathname === '/agent')) {
    const info = {
      ok: true,
      service: 'gatekeeper-agent',
      protocolVersion: 'v1',
      mode: HMAC_SECRET ? 'signed' : 'dev-unsigned',
      ...stats(),
    };
    return sendJson(res, 200, info, { sign: false });
  }
  if (req.method === 'POST' && url.pathname === '/agent') {
    return handlePost(req, res);
  }
  return sendJson(res, 404, { error: 'not found' }, { sign: false });
});

server.listen(PORT, HOST, () => {
  log(`gatekeeper agent listening on http://${HOST}:${PORT} (POST /agent, GET /health)`);
  log(`HMAC: ${HMAC_SECRET ? 'enabled' : 'DISABLED (dev mode)'}`);
  warmChain();
});

// Graceful shutdown (the zkVerifyJS session holds a websocket; without an
// explicit exit the process would linger after SIGTERM).
let shuttingDown = false;
function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  log(`received ${signal} — shutting down`);
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 2000).unref();
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
