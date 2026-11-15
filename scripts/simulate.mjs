// Simulate the platform against a running gatekeeper agent.
// Usage: node scripts/simulate.mjs [baseUrl] [hmacSecret]
//   baseUrl defaults to $GATEKEEPER_URL or http://127.0.0.1:8788
//   secret defaults to $AGENT_GAMES_HMAC_SECRET
// Posts: preflight, a valid task (expect APPROVE + verifiable proof),
// each of the 5 payload traps (expect REJECT + right reason + proof),
// a reused proof_tx (expect REJECT PROOF_REUSED, no proof), and a retry
// of the valid task (expect a byte-identical response). Verifies every
// returned proof against circuits/gatekeeper_vk.json. Exits non-zero on
// any failure. Each run uses fresh random task ids / proof_tx values so it
// is safe to re-run against the same server.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const snarkjs = require('snarkjs');

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(__dirname, '..');
const VK = JSON.parse(fs.readFileSync(path.join(ROOT, 'circuits', 'gatekeeper_vk.json'), 'utf8'));

const base = process.argv[2] ?? process.env.GATEKEEPER_URL ?? 'http://127.0.0.1:8788';
const secret = process.argv[3] ?? process.env.AGENT_GAMES_HMAC_SECRET ?? '';
if (!secret) {
  console.error('no HMAC secret: pass it as arg 2 or set AGENT_GAMES_HMAC_SECRET');
  process.exit(2);
}

const runId = crypto.randomBytes(4).toString('hex');
const VK_HEX = '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';
const VK_OTHER = '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const RECIPIENT = '0x1111111111111111111111111111111111111111';
const RECIPIENT_OTHER = '0x2222222222222222222222222222222222222222';

function tx(n) {
  return `0x${runId}${String(n).padStart(56, '0')}`;
}

function baseInput(overrides = {}) {
  return {
    registered_vk: VK_HEX,
    proof_vk: VK_HEX,
    minimum: '1000',
    public_balance: '5000',
    expiry_block: '9000000',
    current_block: '8999999',
    recipient: RECIPIENT,
    condition_recipient: RECIPIENT,
    amount: '500',
    max_transfer: '1000',
    ...overrides,
  };
}

async function post(pathName, obj, sign = true) {
  const body = JSON.stringify(obj);
  const headers = { 'Content-Type': 'application/json' };
  if (sign) {
    headers['x-agent-games-signature'] = crypto.createHmac('sha256', secret).update(body).digest('hex');
  }
  const t0 = Date.now();
  const res = await fetch(`${base}${pathName}`, { method: 'POST', headers, body });
  const text = await res.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    /* leave null */
  }
  const respSig = res.headers.get('x-agent-games-signature');
  const sigOk = respSig
    ? crypto.timingSafeEqual(Buffer.from(respSig, 'hex'), Buffer.from(crypto.createHmac('sha256', secret).update(text).digest('hex'), 'hex'))
    : false;
  return { status: res.status, json, text, ms: Date.now() - t0, sigOk };
}

async function verifyProof(json) {
  if (!json?.proof || !json?.public_signals) return 'missing';
  try {
    return (await snarkjs.groth16.verify(VK, json.public_signals, json.proof)) ? 'valid' : 'INVALID';
  } catch (e) {
    return `error: ${e.message}`;
  }
}

let failures = 0;
function check(name, ok, detail = '') {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? ` — ${detail}` : ''}`);
  if (!ok) failures += 1;
}

console.log(`Simulating platform against ${base} (run ${runId})`);

// 1. Preflight
{
  const r = await post('/agent', {
    type: 'agent-games.preflight.v1',
    agent_id: 'sim-agent',
    issued_at: new Date().toISOString(),
    nonce: runId,
  });
  check('preflight', r.status === 200 && r.json?.ok === true && r.json?.protocolVersion === 'v1', `HTTP ${r.status}, ${r.ms}ms`);
}

// 2. Valid task -> APPROVE + valid proof
const validTaskId = `gk_sim_${runId}_valid`;
const validInput = baseInput({ proof_tx: tx(1) });
let validBody = null;
{
  const r = await post('/agent', {
    type: 'agent-games.proof-gatekeeper.v1',
    task_id: validTaskId,
    mode: 'practice',
    issued_at: new Date().toISOString(),
    deadline_at: new Date(Date.now() + 60000).toISOString(),
    input: validInput,
  });
  const proofOk = await verifyProof(r.json);
  validBody = r.text;
  check(
    'valid -> APPROVE + proof',
    r.status === 200 && r.json?.decision === 'APPROVE' && r.json?.reason_code === 'VALID_CONDITION' && proofOk === 'valid' && r.sigOk,
    `HTTP ${r.status}, ${r.ms}ms, proof=${proofOk}, resp-signed=${r.sigOk}`,
  );
}

// 3. Retry of the valid task -> identical body
{
  const r = await post('/agent', {
    type: 'agent-games.proof-gatekeeper.v1',
    task_id: validTaskId,
    mode: 'practice',
    issued_at: new Date().toISOString(),
    deadline_at: new Date(Date.now() + 60000).toISOString(),
    input: validInput,
  });
  check('retry -> identical response', r.status === 200 && r.text === validBody, `${r.ms}ms`);
}

// 4. Traps
const traps = [
  ['VK_SUBSTITUTION', { proof_vk: VK_OTHER }],
  ['THRESHOLD_MISMATCH', { public_balance: '999' }],
  ['EXPIRED_CONDITION', { current_block: '9000000' }],
  ['RECIPIENT_MISMATCH', { recipient: RECIPIENT_OTHER }],
  ['AMOUNT_OVERFLOW', { amount: '1001' }],
];
for (const [i, [reason, over]] of traps.entries()) {
  const r = await post('/agent', {
    type: 'agent-games.proof-gatekeeper.v1',
    task_id: `gk_sim_${runId}_${reason.toLowerCase()}`,
    mode: 'practice',
    issued_at: new Date().toISOString(),
    deadline_at: new Date(Date.now() + 60000).toISOString(),
    input: baseInput({ ...over, proof_tx: tx(10 + i) }),
  });
  const proofOk = await verifyProof(r.json);
  check(
    `${reason} -> REJECT + proof`,
    r.status === 200 && r.json?.decision === 'REJECT' && r.json?.reason_code === reason && proofOk === 'valid',
    `HTTP ${r.status}, ${r.ms}ms, proof=${proofOk}`,
  );
}

// 5. Reuse: same proof_tx as the valid task, new task_id
{
  const r = await post('/agent', {
    type: 'agent-games.proof-gatekeeper.v1',
    task_id: `gk_sim_${runId}_reuse`,
    mode: 'practice',
    issued_at: new Date().toISOString(),
    deadline_at: new Date(Date.now() + 60000).toISOString(),
    input: baseInput({ proof_tx: tx(1) }),
  });
  check(
    'reused proof_tx -> REJECT PROOF_REUSED, no proof',
    r.status === 200 && r.json?.decision === 'REJECT' && r.json?.reason_code === 'PROOF_REUSED' && !r.json?.proof,
    `HTTP ${r.status}, ${r.ms}ms`,
  );
}

// 6. Unsigned request rejected
{
  const r = await post('/agent', { type: 'agent-games.preflight.v1' }, false);
  check('unsigned request -> 401', r.status === 401, `HTTP ${r.status}`);
}

console.log(failures === 0 ? '\nAll simulation checks passed.' : `\n${failures} check(s) FAILED.`);
process.exit(failures === 0 ? 0 : 1);
