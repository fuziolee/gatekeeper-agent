// Local Groth16 proof generation for the gatekeeper decision circuit.
//
// Uses snarkjs with the official artifacts:
//   circuits/gatekeeper.wasm, circuits/gatekeeper_final.zkey
//   (vk_hash 0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0,
//    registered on zkVerify mainnet per /api/circuit-info)
//
// The circuit enforces decision correctness (GatekeeperEvaluation, line 102):
// fullProve throws "Assert Failed" when the claimed decision disagrees with
// the checks — e.g. APPROVE on a trap, or REJECT on a valid condition. So a
// proof can only be produced for the CORRECT decision, which is exactly
// what makes it a receipt the platform can trust. For PROOF_REUSED tasks
// there is no proof to submit (all circuit checks pass, so decision=0
// cannot be proven) — callers must omit proof/public_signals there.
//
// Proof generation takes ~300–1000 ms on this VM — far inside the 60 s
// response deadline. Every generated proof is verified locally against the
// shipped verification key before it is returned.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const snarkjs = require('snarkjs');

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CIRCUITS_DIR = path.join(__dirname, '..', 'circuits');
const WASM = path.join(CIRCUITS_DIR, 'gatekeeper.wasm');
const ZKEY = path.join(CIRCUITS_DIR, 'gatekeeper_final.zkey');
const VK_PATH = path.join(CIRCUITS_DIR, 'gatekeeper_vk.json');

let vkPromise = null;
function loadVk() {
  if (!vkPromise) {
    vkPromise = (async () => JSON.parse(await fs.promises.readFile(VK_PATH, 'utf8')))();
  }
  return vkPromise;
}

/** Expected public-signal order (from the circuit): see src/field.js. */
export const PUBLIC_SIGNAL_ORDER = [
  'salt', 'registeredVkHash', 'proofVkHash', 'minimum', 'publicBalance',
  'expiryBlock', 'currentBlock', 'recipient', 'conditionRecipient',
  'amount', 'maxTransfer', 'decision', 'taskId',
];

/**
 * Generate a Groth16 proof for a decision.
 * `inputs` are the 13 circuit input signals from field.encodeTaskInputs().
 * Returns { proof, publicSignals } — proof is the snarkjs proof object,
 * publicSignals is an array of 13 decimal strings in circuit order.
 * Throws when the decision disagrees with the circuit's checks.
 */
export async function generateProof(inputs) {
  const t0 = Date.now();
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(inputs, WASM, ZKEY);
  const vk = await loadVk();
  const valid = await snarkjs.groth16.verify(vk, publicSignals, proof);
  if (!valid) throw new Error('locally generated proof failed self-verification');
  return { proof, publicSignals, ms: Date.now() - t0 };
}
