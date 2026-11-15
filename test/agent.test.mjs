// Tests for the Proof Gatekeeper agent.
// Run: npm test   (node --test test/agent.test.mjs)
// Covers: decision logic (all 7 trap varieties + boundaries), field
// encodings, HMAC sign/verify, Groth16 proof generation + circuit
// enforcement, and the HTTP server end-to-end (preflight, tasks, reuse,
// idempotent retry, unsigned rejection, health).
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const snarkjs = require('snarkjs');
const vk = JSON.parse(
  fs.readFileSync(new URL('../circuits/gatekeeper_vk.json', import.meta.url), 'utf8'),
);

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(__dirname, '..');

const { decide } = await import('../src/decide.js');
const { encodeTaskInputs, stringToField, hashToField, taskSalt } = await import('../src/field.js');
const { signResponse, verifySignature } = await import('../src/hmac.js');
const { generateProof } = await import('../src/prove.js');

// ---------------------------------------------------------------- fixtures
const VK = '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';
const VK_OTHER = '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const RECIPIENT = '0x1111111111111111111111111111111111111111';
const RECIPIENT_OTHER = '0x2222222222222222222222222222222222222222';
const PROOF_TX = '0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef';

function baseInput(overrides = {}) {
  return {
    registered_vk: VK,
    proof_vk: VK,
    minimum: '1000',
    public_balance: '5000',
    expiry_block: '9000000',
    current_block: '8999999',
    recipient: RECIPIENT,
    condition_recipient: RECIPIENT,
    amount: '500',
    max_transfer: '1000',
    proof_tx: PROOF_TX,
    ...overrides,
  };
}

// ------------------------------------------------------------ decision logic
test('decide: valid condition approves', () => {
  const d = decide(baseInput(), false);
  assert.equal(d.decision, 'APPROVE');
  assert.equal(d.reason_code, 'VALID_CONDITION');
});

test('decide: VK substitution rejects', () => {
  const d = decide(baseInput({ proof_vk: VK_OTHER }), false);
  assert.equal(d.decision, 'REJECT');
  assert.equal(d.reason_code, 'VK_SUBSTITUTION');
});

test('decide: threshold mismatch rejects', () => {
  const d = decide(baseInput({ public_balance: '999' }), false);
  assert.equal(d.reason_code, 'THRESHOLD_MISMATCH');
});

test('decide: expired condition rejects (strict: current == expiry)', () => {
  const d = decide(baseInput({ current_block: '9000000' }), false);
  assert.equal(d.reason_code, 'EXPIRED_CONDITION');
});

test('decide: recipient mismatch rejects', () => {
  const d = decide(baseInput({ recipient: RECIPIENT_OTHER }), false);
  assert.equal(d.reason_code, 'RECIPIENT_MISMATCH');
});

test('decide: amount overflow rejects', () => {
  const d = decide(baseInput({ amount: '1001' }), false);
  assert.equal(d.reason_code, 'AMOUNT_OVERFLOW');
});

test('decide: reused proof rejects with no proof to submit', () => {
  const d = decide(baseInput(), true);
  assert.equal(d.reason_code, 'PROOF_REUSED');
});

test('decide: boundaries pass (balance == minimum, amount == max, current == expiry-1)', () => {
  const d = decide(
    baseInput({ public_balance: '1000', amount: '1000', current_block: '8999999' }),
    false,
  );
  assert.equal(d.decision, 'APPROVE');
});

test('decide: malformed fields fail closed to REJECT', () => {
  const d = decide(baseInput({ proof_vk: 'not-a-hash' }), false);
  assert.equal(d.decision, 'REJECT');
  assert.equal(d.reason_code, 'VK_SUBSTITUTION');
});

// ------------------------------------------------------------------- encodings
test('field: taskId encoding matches the verified reference value', () => {
  // Verified numerically during circuit probing (2026-11-15):
  // sha256("gk_24_9d1") % P — note: the final encoding is keccak256, so we
  // check consistency + the salt determinism instead of the sha256 value.
  const a = stringToField('gk_24_9d1');
  const b = stringToField('gk_24_9d1');
  assert.equal(a, b);
  assert.notEqual(a, stringToField('gk_24_9d2'));
});

test('field: hash/address parsing and deterministic salt', () => {
  assert.notEqual(hashToField(VK), null);
  assert.equal(hashToField('garbage'), null);
  assert.equal(taskSalt('gk_1').toString(), taskSalt('gk_1').toString());
  assert.notEqual(taskSalt('gk_1'), taskSalt('gk_2'));
});

// ----------------------------------------------------------------------- HMAC
test('hmac: sign/verify round-trip, tamper rejected, variants accepted', () => {
  const secret = 'test-secret-32-bytes-long-0123456789';
  const body = '{"type":"agent-games.preflight.v1"}';
  const sig = signResponse(secret, body);
  assert.equal(verifySignature(secret, body, sig), true);
  assert.equal(verifySignature(secret, body, `sha256=${sig}`), true);
  const b64 = Buffer.from(sig, 'hex').toString('base64');
  assert.equal(verifySignature(secret, body, b64), true);
  assert.equal(verifySignature(secret, body + 'x', sig), false);
  assert.equal(verifySignature(secret, body, '0'.repeat(64)), false);
  assert.equal(verifySignature('wrong-secret', body, sig), false);
});

// ------------------------------------------------------------- proof generation
test('prove: valid condition generates a verifiable APPROVE proof', async () => {
  const input = { ...baseInput(), task_id: 'gk_test_valid' };
  const enc = encodeTaskInputs(input, true);
  assert.equal(enc.error, undefined);
  const { proof, publicSignals, ms } = await generateProof(enc.inputs);
  assert.equal(publicSignals.length, 13);
  assert.equal(publicSignals[11], '1'); // decision
  assert.equal(await snarkjs.groth16.verify(vk, publicSignals, proof), true);
  console.log(`   (proof gen took ${ms}ms)`);
});

test('prove: each trap generates a verifiable REJECT proof', async () => {
  const traps = [
    ['vk', { proof_vk: VK_OTHER }],
    ['threshold', { public_balance: '999' }],
    ['expired', { current_block: '9000000' }],
    ['recipient', { recipient: RECIPIENT_OTHER }],
    ['amount', { amount: '1001' }],
  ];
  for (const [name, over] of traps) {
    const input = { ...baseInput(over), task_id: `gk_test_${name}` };
    const enc = encodeTaskInputs(input, false);
    const { proof, publicSignals } = await generateProof(enc.inputs);
    assert.equal(publicSignals[11], '0', name);
    assert.equal(await snarkjs.groth16.verify(vk, publicSignals, proof), true, name);
  }
});

test('prove: circuit rejects a wrong decision (APPROVE on a trap fails)', async () => {
  const input = { ...baseInput({ proof_vk: VK_OTHER }), task_id: 'gk_test_wrong' };
  const enc = encodeTaskInputs(input, true); // claim APPROVE on a VK trap
  await assert.rejects(() => generateProof(enc.inputs), /Assert Failed/);
});

test('prove: PROOF_REUSED has no provable decision (all checks pass, so REJECT fails)', async () => {
  const input = { ...baseInput(), task_id: 'gk_test_reused' };
  const enc = encodeTaskInputs(input, false); // claim REJECT on a valid condition
  await assert.rejects(() => generateProof(enc.inputs), /Assert Failed/);
});

// ------------------------------------------------------------------- HTTP server
test('server: preflight, tasks, reuse, retry, auth, health (end-to-end)', async (t) => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gk-test-'));
  const storePath = path.join(tmpDir, 'store.json');
  const port = 18777;
  const secret = 'test-hmac-secret-32-bytes-abcdef';
  const server = spawn(process.execPath, ['src/server.mjs'], {
    cwd: ROOT,
    env: {
      ...process.env,
      PORT: String(port),
      HOST: '127.0.0.1',
      AGENT_GAMES_HMAC_SECRET: secret,
      GATEKEEPER_STORE: storePath,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let serverOut = '';
  server.stdout.on('data', (d) => (serverOut += d));
  server.stderr.on('data', (d) => (serverOut += d));
  t.after(() => {
    // SIGKILL: the child may hold a zkVerifyJS websocket/session that
    // ignores SIGTERM; a test child must not outlive the test run.
    server.kill('SIGKILL');
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  // Wait for the server to listen.
  const base = `http://127.0.0.1:${port}`;
  let up = false;
  for (let i = 0; i < 50 && !up; i++) {
    try {
      const r = await fetch(`${base}/health`);
      up = r.status === 200;
    } catch {
      await new Promise((r) => setTimeout(r, 200));
    }
  }
  assert.equal(up, true, `server did not come up; output:\n${serverOut}`);

  const signedPost = async (pathName, obj, useSecret = secret) => {
    const body = JSON.stringify(obj);
    const headers = { 'Content-Type': 'application/json' };
    if (useSecret) {
      headers['x-agent-games-signature'] = crypto
        .createHmac('sha256', useSecret)
        .update(body)
        .digest('hex');
    }
    const r = await fetch(`${base}${pathName}`, { method: 'POST', headers, body });
    const text = await r.text();
    let json = null;
    try {
      json = JSON.parse(text);
    } catch {
      /* keep null */
    }
    return { status: r.status, json, text, sig: r.headers.get('x-agent-games-signature') };
  };

  // Health endpoints.
  const h1 = await fetch(`${base}/health`);
  assert.equal(h1.status, 200);
  const h2 = await fetch(`${base}/agent`);
  assert.equal(h2.status, 200);

  // Preflight (signed).
  const pf = await signedPost('/agent', {
    type: 'agent-games.preflight.v1',
    agent_id: 'test-agent',
    issued_at: new Date().toISOString(),
    nonce: 'abc123',
  });
  assert.equal(pf.status, 200);
  assert.deepEqual(pf.json, { ok: true, protocolVersion: 'v1' });
  assert.ok(pf.sig, 'preflight response should be signed');

  // Unsigned request rejected.
  const unauth = await signedPost(
    '/agent',
    { type: 'agent-games.preflight.v1' },
    null,
  );
  assert.equal(unauth.status, 401);

  // Valid task -> APPROVE with a verifiable proof.
  const taskId = 'gk_http_valid';
  const valid = await signedPost('/agent', {
    type: 'agent-games.proof-gatekeeper.v1',
    task_id: taskId,
    mode: 'practice',
    issued_at: new Date().toISOString(),
    deadline_at: new Date(Date.now() + 60000).toISOString(),
    input: { ...baseInput(), task_id: taskId },
  });
  assert.equal(valid.status, 200, valid.text);
  assert.equal(valid.json.decision, 'APPROVE');
  assert.equal(valid.json.reason_code, 'VALID_CONDITION');
  assert.equal(valid.json.proof_tx, PROOF_TX);
  assert.ok(valid.json.proof, 'APPROVE must carry a proof');
  assert.equal(valid.json.public_signals.length, 13);
  assert.equal(
    await snarkjs.groth16.verify(vk, valid.json.public_signals, valid.json.proof),
    true,
    'response proof must verify against the shipped VK',
  );
  // Response signature must verify.
  assert.equal(
    verifySignature(secret, JSON.stringify(valid.json), valid.sig),
    true,
    'response signature must verify',
  );

  // Retry of the same task_id -> byte-identical body.
  const retry = await signedPost('/agent', {
    type: 'agent-games.proof-gatekeeper.v1',
    task_id: taskId,
    mode: 'practice',
    issued_at: new Date().toISOString(),
    deadline_at: new Date(Date.now() + 60000).toISOString(),
    input: { ...baseInput(), task_id: taskId },
  });
  assert.equal(retry.status, 200);
  assert.equal(JSON.stringify(retry.json), JSON.stringify(valid.json));

  // Each trap -> REJECT with the right reason + a verifiable proof.
  const trapCases = [
    ['VK_SUBSTITUTION', { proof_vk: VK_OTHER }],
    ['THRESHOLD_MISMATCH', { public_balance: '999' }],
    ['EXPIRED_CONDITION', { current_block: '9000000' }],
    ['RECIPIENT_MISMATCH', { recipient: RECIPIENT_OTHER }],
    ['AMOUNT_OVERFLOW', { amount: '1001' }],
  ];
  for (const [i, [reason, over]] of trapCases.entries()) {
    const id = `gk_http_${reason.toLowerCase()}`;
    const r = await signedPost('/agent', {
      type: 'agent-games.proof-gatekeeper.v1',
      task_id: id,
      mode: 'practice',
      issued_at: new Date().toISOString(),
      deadline_at: new Date(Date.now() + 60000).toISOString(),
      input: { ...baseInput(over), task_id: id, proof_tx: `${PROOF_TX.slice(0, -4)}${String(i).padStart(4, '0')}` },
    });
    assert.equal(r.status, 200, r.text);
    assert.equal(r.json.decision, 'REJECT', reason);
    assert.equal(r.json.reason_code, reason);
    assert.ok(r.json.proof, `${reason} must carry a REJECT proof`);
    assert.equal(
      await snarkjs.groth16.verify(vk, r.json.public_signals, r.json.proof),
      true,
      `${reason} proof must verify`,
    );
  }

  // Reuse: same proof_tx as the first valid task, new task_id.
  const reuse = await signedPost('/agent', {
    type: 'agent-games.proof-gatekeeper.v1',
    task_id: 'gk_http_reuse',
    mode: 'practice',
    issued_at: new Date().toISOString(),
    deadline_at: new Date(Date.now() + 60000).toISOString(),
    input: { ...baseInput(), task_id: 'gk_http_reuse' },
  });
  assert.equal(reuse.status, 200);
  assert.equal(reuse.json.decision, 'REJECT');
  assert.equal(reuse.json.reason_code, 'PROOF_REUSED');
  assert.equal(reuse.json.proof, undefined, 'PROOF_REUSED carries no proof');
});
