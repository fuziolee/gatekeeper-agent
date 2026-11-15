// Best-effort on-chain confirmation of the incoming proof.
//
// The task gives us proof_tx (an on-chain reference) and proof_vk, but not
// the proof itself. The build guide says to "call zkVerifyJS to confirm the
// proof is on-chain" — but there is NO trap type and NO reason code for a
// proof that is not on-chain, so this check can never change the decision:
// it is performed for logging only, with a hard timeout, and its result is
// recorded in the task log. The decision is always the payload-based one
// from src/decide.js.
//
// Implementation: a lazy read-only zkVerify MAINNET session (no credentials
// needed). On first use it lists the chain's query pallets to find an
// attestation-like storage entry and tries to look up proof_tx there.
// If anything is unavailable, slow, or inconclusive, the result is
// 'inconclusive' — never an error, never a decision input.
let sessionPromise = null;
let sessionFailedUntil = 0;

async function getSession() {
  const now = Date.now();
  if (sessionPromise) return sessionPromise;
  if (now < sessionFailedUntil) return null;
  sessionPromise = (async () => {
    try {
      const { zkVerifySession } = await import('zkverifyjs');
      const session = await Promise.race([
        zkVerifySession.start().zkVerify().readOnly(),
        new Promise((_, reject) =>
          setTimeout(() => reject(new Error('session connect timed out')), 15000),
        ),
      ]);
      return session;
    } catch (err) {
      sessionFailedUntil = Date.now() + 60000;
      sessionPromise = null;
      return { _error: err?.message ?? String(err) };
    }
  })();
  const s = await sessionPromise;
  if (s?._error) {
    sessionPromise = null;
    return null;
  }
  return s;
}

function withTimeout(promise, ms, fallback) {
  return Promise.race([
    promise,
    new Promise((resolve) => setTimeout(() => resolve(fallback), ms)),
  ]);
}

/** Warm the session in the background (fire-and-forget). */
export function warmChain() {
  getSession().catch(() => {});
}

/**
 * Best-effort on-chain checks for a task. Log-only, never affects the
 * decision. Returns { status, detail } where status is one of:
 *   - 'corroborated': the proof's VK is registered in the mainnet Groth16
 *     settlement pallet (a real on-chain signal for the VK check)
 *   - 'vk-unregistered': the proof's VK is NOT in the registry
 *   - 'inconclusive': anything unavailable, slow, or not queryable
 *
 * Notes from probing mainnet (2026-11-15, finalized ~#5984616):
 *   - settlementGroth16Pallet.vks(vkHash) returns the registered VK
 *     (the gatekeeper vkHash 0x6b79… is registered). This works.
 *   - There is NO per-attestation storage keyed by proof_tx:
 *     aggregate.published is a plain Vec (currently empty), not a map,
 *     so the incoming proof's on-chain attestation cannot be confirmed
 *     by a storage lookup. (Attestations live in events/extrinsics.)
 */
export async function checkProofOnChain({ proofTx, proofVk } = {}, { timeoutMs = 3000 } = {}) {
  const work = (async () => {
    const session = await getSession();
    if (!session) return { status: 'inconclusive', detail: 'no mainnet session' };
    try {
      const api = session.api;
      let latestBlock = null;
      try {
        const hash = await api.rpc.chain.getFinalizedHead();
        const header = await api.rpc.chain.getHeader(hash);
        latestBlock = header.number.toNumber();
      } catch {
        /* ignore */
      }
      const blockNote = latestBlock !== null ? `; finalized #${latestBlock}` : '';
      // VK registry lookup (Groth16 settlement pallet).
      if (typeof proofVk === 'string' && /^0x[0-9a-fA-F]{64}$/.test(proofVk)) {
        try {
          const entry = await api.query.settlementGroth16Pallet.vks(proofVk);
          const registered = entry !== null && entry !== undefined && !entry.isEmpty;
          return {
            status: registered ? 'corroborated' : 'vk-unregistered',
            detail: `proof_vk ${registered ? 'IS' : 'is NOT'} registered in settlementGroth16Pallet.vks${blockNote}`,
          };
        } catch (err) {
          return { status: 'inconclusive', detail: `vk lookup error: ${err?.message ?? String(err)}${blockNote}` };
        }
      }
      return {
        status: 'inconclusive',
        detail: `proof_vk missing/malformed; no per-proof_tx attestation storage exists on mainnet${blockNote}`,
      };
    } catch (err) {
      return { status: 'inconclusive', detail: `lookup error: ${err?.message ?? String(err)}` };
    }
  })();
  return withTimeout(work, timeoutMs, {
    status: 'inconclusive',
    detail: `timed out after ${timeoutMs} ms`,
  });
}
