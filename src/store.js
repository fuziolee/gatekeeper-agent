// Persistent local state: proof-reuse seen-set + idempotent response cache.
//
// - seenProofs: proof_tx values observed in processed tasks (any decision).
//   A NEW task_id reusing a seen proof_tx is a PROOF_REUSED trap.
// - responses: task_id -> the exact JSON body already returned, so a
//   platform retry of the same task_id gets a byte-identical response.
//
// State lives in data/store.json (git-ignored) and is written synchronously
// on every mutation — volume is tiny (8 tasks/round), correctness matters
// more than write throughput. All mutations happen synchronously inside the
// request handler (Node is single-threaded), so check-and-record is atomic.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const STORE_PATH =
  process.env.GATEKEEPER_STORE ?? path.join(__dirname, '..', 'data', 'store.json');

function load() {
  try {
    const raw = JSON.parse(fs.readFileSync(STORE_PATH, 'utf8'));
    const seen = Array.isArray(raw.seenProofs) ? raw.seenProofs : [];
    // seenProofs may be an array of proof_tx (old) or [proof_tx, task_id] pairs.
    const seenMap = new Map();
    for (const entry of seen) {
      if (Array.isArray(entry)) seenMap.set(entry[0], entry[1]);
      else seenMap.set(entry, null);
    }
    return {
      seenProofs: seenMap,
      responses: new Map(Object.entries(raw.responses ?? {})),
    };
  } catch {
    return { seenProofs: new Map(), responses: new Map() };
  }
}

let state = load();

function save() {
  fs.mkdirSync(path.dirname(STORE_PATH), { recursive: true });
  const tmp = `${STORE_PATH}.tmp`;
  fs.writeFileSync(
    tmp,
    JSON.stringify(
      { seenProofs: [...state.seenProofs], responses: Object.fromEntries(state.responses) },
      null,
      2,
    ),
  );
  fs.renameSync(tmp, STORE_PATH);
}

export function hasResponse(taskId) {
  return state.responses.has(taskId);
}

export function getResponse(taskId) {
  return state.responses.get(taskId) ?? null;
}

export function saveResponse(taskId, body) {
  state.responses.set(taskId, body);
  save();
}

export function isProofSeen(proofTx, taskId) {
  if (typeof proofTx !== 'string' || proofTx.length === 0) return false;
  const firstTask = state.seenProofs.get(proofTx.toLowerCase());
  // Seen with a DIFFERENT task_id = reuse. Same task_id = platform retry.
  return firstTask !== undefined && firstTask !== null && firstTask !== taskId;
}

export function markProofSeen(proofTx, taskId) {
  if (typeof proofTx !== 'string' || proofTx.length === 0) return;
  const key = proofTx.toLowerCase();
  if (!state.seenProofs.has(key)) {
    state.seenProofs.set(key, taskId ?? null);
    save();
  }
}

export function stats() {
  return { seenProofs: state.seenProofs.size, cachedResponses: state.responses.size };
}
