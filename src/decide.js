// Pure decision logic for Proof Gatekeeper.
//
// The circuit (GatekeeperEvaluation) enforces exactly this rule — verified
// empirically against the shipped wasm/zkey (see test/agent.test.mjs):
//   APPROVE (decision=1)  iff  ALL of these hold:
//     registered_vk == proof_vk
//     public_balance >= minimum            (equality passes)
//     recipient == condition_recipient     (case-insensitive)
//     current_block < expiry_block         (STRICT — equality counts as expired)
//     amount <= max_transfer               (equality passes)
//   REJECT (decision=0) otherwise, with the reason of the first failing
//   check in the priority order below. The platform generates one trap per
//   task, so priority only matters when several traps coincide; the order
//   below is documented and deterministic.
//
// Proof reuse is NOT checkable by the circuit (it has no memory of past
// tasks): it is enforced here against the agent's local seen-set, keyed by
// proof_tx. A task whose task_id was already answered is a platform retry,
// not a reuse — callers must check idempotency first (see store.js).
//
// Scoring reminder: wrong APPROVE −6, wrong REJECT −3, so when in doubt
// the agent leans REJECT (fail closed).
import { decimalToBigInt } from './field.js';

export const REASONS = {
  VALID: 'VALID_CONDITION',
  VK: 'VK_SUBSTITUTION',
  THRESHOLD: 'THRESHOLD_MISMATCH',
  REUSED: 'PROOF_REUSED',
  EXPIRED: 'EXPIRED_CONDITION',
  RECIPIENT: 'RECIPIENT_MISMATCH',
  AMOUNT: 'AMOUNT_OVERFLOW',
};

function normHex(v) {
  return typeof v === 'string' ? v.trim().toLowerCase() : null;
}

/**
 * Decide a task. `input` is the task's `input` object; `isReused` is true
 * when proof_tx is already in the local seen-set.
 * Returns { decision: 'APPROVE'|'REJECT', reason_code, checks }.
 * `checks` records each individual check (true = passed) for logging.
 * Malformed fields fail closed to REJECT with the most plausible reason.
 */
export function decide(input, isReused) {
  const checks = {
    reused: false,
    vkMatch: false,
    notExpired: false,
    recipientMatch: false,
    thresholdMet: false,
    amountOk: false,
  };

  if (isReused) {
    checks.reused = true;
    return { decision: 'REJECT', reason_code: REASONS.REUSED, checks };
  }

  // VK match (string compare — the circuit compares the encoded values,
  // which is equivalent when the same encoding is used for both).
  const registeredVk = normHex(input.registered_vk);
  const proofVk = normHex(input.proof_vk);
  if (registeredVk === null || proofVk === null) {
    return { decision: 'REJECT', reason_code: REASONS.VK, checks };
  }
  checks.vkMatch = registeredVk === proofVk;
  if (!checks.vkMatch) {
    return { decision: 'REJECT', reason_code: REASONS.VK, checks };
  }

  // Expiry: APPROVE only while current_block < expiry_block (strict).
  const expiryBlock = decimalToBigInt(input.expiry_block);
  const currentBlock = decimalToBigInt(input.current_block);
  if (expiryBlock === null || currentBlock === null) {
    return { decision: 'REJECT', reason_code: REASONS.EXPIRED, checks };
  }
  checks.notExpired = currentBlock < expiryBlock;
  if (!checks.notExpired) {
    return { decision: 'REJECT', reason_code: REASONS.EXPIRED, checks };
  }

  // Recipient match.
  const recipient = normHex(input.recipient);
  const conditionRecipient = normHex(input.condition_recipient);
  if (recipient === null || conditionRecipient === null) {
    return { decision: 'REJECT', reason_code: REASONS.RECIPIENT, checks };
  }
  checks.recipientMatch = recipient === conditionRecipient;
  if (!checks.recipientMatch) {
    return { decision: 'REJECT', reason_code: REASONS.RECIPIENT, checks };
  }

  // Threshold: public_balance >= minimum.
  const minimum = decimalToBigInt(input.minimum);
  const publicBalance = decimalToBigInt(input.public_balance);
  if (minimum === null || publicBalance === null) {
    return { decision: 'REJECT', reason_code: REASONS.THRESHOLD, checks };
  }
  checks.thresholdMet = publicBalance >= minimum;
  if (!checks.thresholdMet) {
    return { decision: 'REJECT', reason_code: REASONS.THRESHOLD, checks };
  }

  // Amount cap: amount <= max_transfer.
  const amount = decimalToBigInt(input.amount);
  const maxTransfer = decimalToBigInt(input.max_transfer);
  if (amount === null || maxTransfer === null) {
    return { decision: 'REJECT', reason_code: REASONS.AMOUNT, checks };
  }
  checks.amountOk = amount <= maxTransfer;
  if (!checks.amountOk) {
    return { decision: 'REJECT', reason_code: REASONS.AMOUNT, checks };
  }

  return { decision: 'APPROVE', reason_code: REASONS.VALID, checks };
}
