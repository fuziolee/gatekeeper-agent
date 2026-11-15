# Proof Gatekeeper — zkVerify Agent Games

A live agent for the **Proof Gatekeeper** track of zkVerify Agent Games
(https://agentgames.zkverify.io). It verifies ZK-proof-backed payment tasks
and answers APPROVE / REJECT with a Groth16 proof of its own decision.

## How it works

```
platform POST /agent  ──HMAC──>  verify signature (raw body)
                                  -> parse envelope
                                  -> preflight? answer {ok:true, protocolVersion:"v1"}
                                  -> task? decide + prove + answer (signed)
```

### Task envelope (incoming)

```json
{
  "type": "agent-games.proof-gatekeeper.v1",
  "task_id": "gk_24_9d1",
  "mode": "competition",
  "issued_at": "2026-11-15T10:00:00Z",
  "deadline_at": "2026-11-15T10:01:00Z",
  "input": {
    "registered_vk": "0x…",
    "proof_vk": "0x…",
    "minimum": "1000",
    "public_balance": "5000",
    "expiry_block": "9000000",
    "current_block": "8999999",
    "recipient": "0x…",
    "condition_recipient": "0x…",
    "amount": "500",
    "max_transfer": "1000",
    "proof_tx": "0x…"
  }
}
```

60 s hard deadline per task. Scoring: correct +12, wrong APPROVE −6,
wrong REJECT −3, timeout −2, missing/invalid proof −2, reliability bonus 0–+5.
A wrong APPROVE is the most expensive mistake, so the agent fails closed:
any doubt or error → REJECT.

### Decision rules (all payload-based)

APPROVE iff **all** hold, else REJECT with the first failing reason:

| check | fail reason |
|---|---|
| `proof_tx` already seen with a different task | `PROOF_REUSED` |
| `proof_vk == registered_vk` | `VK_SUBSTITUTION` |
| `current_block < expiry_block` (strict — equality is expired) | `EXPIRED_CONDITION` |
| `recipient == condition_recipient` | `RECIPIENT_MISMATCH` |
| `public_balance >= minimum` | `THRESHOLD_MISMATCH` |
| `amount <= max_transfer` | `AMOUNT_OVERFLOW` |
| all pass | `VALID_CONDITION` (APPROVE) |

### Response (outgoing, signed with `x-agent-games-signature`)

```json
{
  "decision": "APPROVE",
  "reason_code": "VALID_CONDITION",
  "proof": { "pi_a": […], "pi_b": […], "pi_c": […], "protocol": "groth16", "curve": "bn128" },
  "public_signals": ["<salt>", "<registeredVkHash>", "<proofVkHash>", "<minimum>", "<publicBalance>",
                     "<expiryBlock>", "<currentBlock>", "<recipient>", "<conditionRecipient>",
                     "<amount>", "<maxTransfer>", "<decision>", "<taskId>"],
  "proof_tx": "0x…"
}
```

`proof` / `public_signals` are omitted **only** for `PROOF_REUSED` (no proof
can be generated for it — see below) and if proof generation itself fails
(the decision is still answered; that costs −2 instead of the +12…+17).

### The decision proof

The platform publishes the gatekeeper circuit at
`https://agentgames.zkverify.io/api/circuit-info`:

- network: `mainnet`; gatekeeper `vkHash`
  `0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`
- `circuits/gatekeeper.wasm` (1,755,820 bytes),
  `circuits/gatekeeper_final.zkey` (309,750 bytes),
  `circuits/gatekeeper_vk.json` (Groth16/BN128, 13 public inputs)

The circuit (`GatekeeperEvaluation`, 13 public inputs, no private inputs)
enforces decision correctness: `fullProve` throws unless the claimed
decision matches the checks, so a proof can only be produced for the
correct decision — it is a receipt the platform can trust. Verified
empirically: APPROVE on a trap fails; REJECT on a valid condition fails;
`PROOF_REUSED` (all checks pass, decision must be 0) is unprovable by
construction, matching the docs' "no proof to submit". Proof generation
takes ~1 s on this VM — far inside the 60 s deadline. Every proof is
verified locally against the shipped VK before being returned.

Public-signal order: `[salt, registeredVkHash, proofVkHash, minimum,
publicBalance, expiryBlock, currentBlock, recipient, conditionRecipient,
amount, maxTransfer, decision, taskId]`. Encodings (see `src/field.js`):
32-byte hashes → `BigInt(hex) % P`; task id → `keccak256(utf8) % P`;
addresses → `BigInt(address)`; numbers → `BigInt(decimal)`; salt →
`keccak256("agent-games.gatekeeper.salt:" + taskId) % P` (deterministic per
task, so retries are byte-identical).

### HMAC

`x-agent-games-signature` over the raw body, HMAC-SHA256 hex (the standard
choice — the docs do not state the algorithm; verification also accepts
`sha256=<hex>` and base64 forms). Every inbound POST is verified before
parsing; every response is signed. Secret from `AGENT_GAMES_HMAC_SECRET`
(env or `.env`). **Without a secret the server runs in dev mode and
accepts unsigned requests — set the secret before registering.**

### On-chain confirmation (best-effort, log-only)

The task carries no proof, only `proof_tx`, and there is no trap type or
reason code for "proof not on-chain", so the decision can never depend on
it. The agent opens a read-only zkVerify **mainnet** session (no
credentials) and, per task, checks whether `proof_vk` is registered in
`settlementGroth16Pallet.vks` — a real on-chain signal (the gatekeeper
vkHash `0x6b79…` is registered; a substituted VK is not). The result is
logged with the task, never used for the decision. There is **no**
per-attestation storage keyed by `proof_tx` on mainnet
(`aggregate.published` is a plain Vec, currently empty), so the incoming
proof's attestation itself cannot be confirmed by a storage lookup.
No Kurier mainnet API key and no funded mainnet account exist, so this is
best-effort only.

### Reuse & idempotency

`data/store.json` (git-ignored) persists a `proof_tx → task_id` map and a
`task_id → response` cache. A new task reusing a seen `proof_tx` →
`PROOF_REUSED`. A retry of the same `task_id` returns the cached response
byte-for-byte. Practice tasks are recorded the same way as competition
tasks (the platform's practice proofs are distinct, so they cannot poison
the competition seen-set — if a practice proof_tx ever collided with a
competition one, that would be a platform reuse by definition).

## Run it

```bash
cp .env.example .env   # fill in AGENT_GAMES_HMAC_SECRET after rotating it
npm install
npm test               # 17 tests: decision logic, encodings, HMAC, proofs, HTTP e2e
scripts/start.sh       # starts server + cloudflared tunnel, prints public URL
node scripts/simulate.mjs <public-url> <secret>   # platform-style simulation
scripts/start.sh stop  # stop server + tunnel
```

Server listens on `127.0.0.1:8788` (`POST /agent`, `GET /health`, `GET /`).
The agent is fully working locally, but **there is currently no public
endpoint**: this VM has no direct egress — all traffic goes through an HTTP
egress proxy that (a) BLOCKS `api.trycloudflare.com` (403 "Your request was
blocked"), so cloudflared quick tunnels cannot register, and (b) blackholes
CONNECT to non-443 ports (verified: no SSH banner from `github.com:22`), so
localtunnel's raw-TCP data plane can never connect (its edge answers 503
"Tunnel Unavailable" even with live data connections). The localtunnel
driver in `scripts/tunnel-lt.mjs` is kept for reference (it correctly
assigns the fixed subdomain `gatekeeper-fuziole.loca.lt` and opens data
connections — the packets just never arrive). The shared egress IP is now
also rate-limited by localtunnel.me ("Forbidden" on new assignments).

To get a public endpoint, one of these is needed:
1. **Cloudflare account + API token** → named tunnel created via the API
   (`api.cloudflare.com` IS reachable through the proxy) + `cloudflared
   --protocol http2` (forces the edge connection over 443). Residual risk:
   unproven whether cloudflared honors the egress proxy for its edge
   connection — test after creating the tunnel.
2. **ngrok authtoken** (free signup; `api.ngrok.com` reachable; the ngrok
   agent honors `HTTPS_PROXY`).
3. **Tailscale Funnel** if the user has Tailscale
   (`controlplane.tailscale.com` reachable).
4. **Run the agent on a host with direct egress** (user machine / VPS) —
   copy this repo, `npm install`, set `AGENT_GAMES_HMAC_SECRET`, run
   `scripts/start.sh` (the localtunnel driver should work there, or use
   cloudflared).

Until one of those is in place, the agent cannot be registered or
preflighted: the dashboard needs a reachable endpoint URL first.

## Registration checklist (dashboard, done by the main agent)

1. Register the agent in the dashboard: name, Gatekeeper checkbox,
   public GitHub repo URL (this repo, on the personal account), endpoint
   `https://<tunnel>/agent`.
2. **Rotate Secret** in the dashboard, copy the one-time plaintext, put it
   in `.env` as `AGENT_GAMES_HMAC_SECRET`, restart (`scripts/start.sh`).
3. Run the platform preflight (dashboard sends the signed preflight; the
   agent answers `{ok:true, protocolVersion:"v1"}`).
4. Do 1 unscored practice task (dashboard) and check the server log for
   `decision=… reason=… proof=yes`.
5. Verify the agent shows as active before Round 3 opens (15 Nov 17:30 WIB).

## Risks / spec gaps (read before registering)

- **HMAC algorithm is undocumented** — HMAC-SHA256 hex is the assumed
  standard. If preflight fails with a signature error, the encoding is the
  first thing to revisit (see `src/hmac.js`).
- **Circuit input encodings are undocumented** — the encodings in
  `src/field.js` are the most standard choices; the circuit only constrains
  relationships between inputs, and the platform scores the decision
  independently, so a mismatch would at most cost the reliability bonus, not
  the decision score. If practice reveals a mismatch, `src/field.js` is the
  single place to change it.
- **No public endpoint from this VM (blocker)** — the egress proxy blocks
  `api.trycloudflare.com` (cloudflared registration) and blackholes
  non-443 TCP (localtunnel data plane, SSH tunnels). See "Run it" above
  for the four ways to get a public endpoint. The server must be running
  17:30–03:30 WIB every round night; after a VM restart, re-run
  `scripts/start.sh` (the server restarts in dev mode until the HMAC
  secret is set).
- **No on-chain proof verification** — without a Kurier mainnet API key or
  a funded mainnet account, the incoming proof's on-chain status is
  best-effort only; the decision is payload-based, which matches the
  documented trap set.
- The 5th prize-eligibility requirement on the Agent Games account is
  still unknown (4 of 5 met at last check).

## Files

- `src/server.mjs` — HTTP server, HMAC, preflight, task handling
- `src/decide.js` — pure decision logic + reason codes
- `src/field.js` — circuit input encodings
- `src/prove.js` — snarkjs Groth16 proof generation + local verification
- `src/hmac.js` — HMAC-SHA256 sign/verify
- `src/onchain.js` — best-effort zkVerify mainnet attestation lookup
- `src/store.js` — persistent seen-set + response cache
- `circuits/` — gatekeeper.wasm, gatekeeper_final.zkey, gatekeeper_vk.json
- `test/agent.test.mjs` — 17 tests (all passing, ~13 s)
- `scripts/simulate.mjs` — platform-style simulation against a live server
- `scripts/start.sh` — start/stop server + tunnel
