// Field-element encodings for the gatekeeper circuit's 13 public inputs.
//
// The circuit (GatekeeperEvaluation, Circom 2 / Groth16 / BN128) takes 13
// public inputs, in this public-signal order (verified empirically against
// the shipped wasm/zkey — see test/agent.test.mjs):
//   [salt, registeredVkHash, proofVkHash, minimum, publicBalance,
//    expiryBlock, currentBlock, recipient, conditionRecipient,
//    amount, maxTransfer, decision, taskId]
//
// Encodings (all values reduced mod the BN128 scalar field prime):
//   - 32-byte hashes (registeredVkHash, proofVkHash): BigInt(hex) % P
//   - taskId (string, e.g. "gk_24_9d1"): keccak256(utf8) % P
//   - addresses (20-byte hex): BigInt(hex)
//   - amounts / block heights: BigInt(decimal)
//   - decision: 1 = APPROVE, 0 = REJECT
//   - salt: keccak256("agent-games.gatekeeper.salt:" + taskId) % P
//     (deterministic per task, so a retried task gets a byte-identical
//     response — the platform treats task_id as an idempotency key)
//
// NOTE ON ENCODING RISK: the platform's docs do not state the encoding it
// uses when it re-checks public signals against a task. The circuit itself
// only constrains RELATIONSHIPS between the inputs (equality of the two VK
// hashes, comparisons of the numbers/addresses, decision == f(checks)), so
// any consistent encoding satisfies the circuit. The platform scores the
// decision independently and re-verifies the proof against its own VK, so
// the encodings above (the most standard choices: BigInt % P for hashes,
// keccak256 % P for strings, matching the platform's documented keccak256
// usage elsewhere) are the best-supported guess. If preflight/practice
// reveals a mismatch, this file is the single place to change it.
import { keccak_256 } from '@noble/hashes/sha3.js';

export const FIELD_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

export function toField(value) {
  const v = BigInt(value);
  return ((v % FIELD_PRIME) + FIELD_PRIME) % FIELD_PRIME;
}

/** 32-byte hex hash (0x...) -> field element. Returns null if unparseable. */
export function hashToField(hex) {
  if (typeof hex !== 'string') return null;
  const h = hex.trim().toLowerCase();
  if (!/^0x[0-9a-f]+$/.test(h)) return null;
  try {
    return toField(BigInt(h));
  } catch {
    return null;
  }
}

/** Arbitrary string (e.g. task id) -> field element via keccak256. */
export function stringToField(s) {
  const bytes = new TextEncoder().encode(String(s));
  const digest = keccak_256(bytes);
  let v = 0n;
  for (const b of digest) v = (v << 8n) | BigInt(b);
  return toField(v);
}

/** 20-byte hex address -> field element. Returns null if unparseable. */
export function addressToField(addr) {
  if (typeof addr !== 'string') return null;
  const a = addr.trim().toLowerCase();
  if (!/^0x[0-9a-f]{40}$/.test(a)) return null;
  try {
    return BigInt(a);
  } catch {
    return null;
  }
}

/** Decimal string/number -> BigInt. Returns null if unparseable. */
export function decimalToBigInt(v) {
  if (typeof v === 'bigint') return v;
  if (typeof v === 'number' && Number.isInteger(v)) return BigInt(v);
  if (typeof v === 'string' && /^-?\d+$/.test(v.trim())) {
    try {
      return BigInt(v.trim());
    } catch {
      return null;
    }
  }
  return null;
}

/** Deterministic per-task salt: keccak256("agent-games.gatekeeper.salt:" + taskId) % P */
export function taskSalt(taskId) {
  return stringToField(`agent-games.gatekeeper.salt:${taskId}`);
}

/**
 * Encode a task's input fields into the circuit's 13 input signals.
 * Returns { inputs } on success or { error } when a field is malformed.
 * `inputs` keys are the circuit's signal names; values are decimal strings.
 */
export function encodeTaskInputs(input, decision) {
  const registeredVkHash = hashToField(input.registered_vk);
  const proofVkHash = hashToField(input.proof_vk);
  const minimum = decimalToBigInt(input.minimum);
  const publicBalance = decimalToBigInt(input.public_balance);
  const expiryBlock = decimalToBigInt(input.expiry_block);
  const currentBlock = decimalToBigInt(input.current_block);
  const recipient = addressToField(input.recipient);
  const conditionRecipient = addressToField(input.condition_recipient);
  const amount = decimalToBigInt(input.amount);
  const maxTransfer = decimalToBigInt(input.max_transfer);
  const taskId = typeof input.task_id === 'string' && input.task_id.length > 0
    ? stringToField(input.task_id)
    : null;

  const bad = [];
  if (registeredVkHash === null) bad.push('registered_vk');
  if (proofVkHash === null) bad.push('proof_vk');
  if (minimum === null) bad.push('minimum');
  if (publicBalance === null) bad.push('public_balance');
  if (expiryBlock === null) bad.push('expiry_block');
  if (currentBlock === null) bad.push('current_block');
  if (recipient === null) bad.push('recipient');
  if (conditionRecipient === null) bad.push('condition_recipient');
  if (amount === null) bad.push('amount');
  if (maxTransfer === null) bad.push('max_transfer');
  if (taskId === null) bad.push('task_id');
  if (bad.length > 0) return { error: `malformed fields: ${bad.join(', ')}` };

  const taskIdStr = String(input.task_id);
  return {
    inputs: {
      salt: taskSalt(taskIdStr).toString(),
      registeredVkHash: registeredVkHash.toString(),
      proofVkHash: proofVkHash.toString(),
      minimum: minimum.toString(),
      publicBalance: publicBalance.toString(),
      expiryBlock: expiryBlock.toString(),
      currentBlock: currentBlock.toString(),
      recipient: recipient.toString(),
      conditionRecipient: conditionRecipient.toString(),
      amount: amount.toString(),
      maxTransfer: maxTransfer.toString(),
      decision: decision ? '1' : '0',
      taskId: taskId.toString(),
    },
  };
}
