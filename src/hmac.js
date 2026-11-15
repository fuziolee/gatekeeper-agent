// HMAC-SHA256 signing/verification for the Agent Games platform.
//
// Docs (rules + build guide) state: the platform signs every task request
// with the agent's 32-byte HMAC secret in the `x-agent-games-signature`
// header, computed over the RAW request body, and the agent must sign every
// response the same way. The hash algorithm and header encoding are NOT
// specified anywhere in the docs, so this module implements the standard
// choice — HMAC-SHA256, hex-encoded — and accepts the common variants when
// verifying inbound requests:
//   - plain hex (expected)
//   - "sha256=<hex>" (GitHub-style prefix)
//   - base64 of the raw HMAC bytes
// Outbound responses are signed as plain hex. If preflight fails with a
// signature error, the encoding is the first thing to revisit.
import crypto from 'node:crypto';

export function hmacHex(secret, rawBody) {
  return crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
}

/** Sign a raw response body. Returns the header value to send. */
export function signResponse(secret, rawBody) {
  if (!secret) return null;
  return hmacHex(secret, rawBody);
}

/**
 * Verify an inbound signature header against the raw request body.
 * Returns true on match. Accepts hex, "sha256=<hex>", and base64 forms.
 * Uses timing-safe comparison.
 */
export function verifySignature(secret, rawBody, headerValue) {
  if (!secret || typeof headerValue !== 'string') return false;
  const expectedHex = hmacHex(secret, rawBody);
  const candidates = [];
  const h = headerValue.trim();
  candidates.push(h);
  if (h.toLowerCase().startsWith('sha256=')) candidates.push(h.slice(7));
  // base64 form: decode to bytes, re-encode as hex
  try {
    const b64 = Buffer.from(h, 'base64');
    if (b64.length === 32) candidates.push(b64.toString('hex'));
  } catch {
    /* not base64 */
  }
  const expectedBuf = Buffer.from(expectedHex, 'hex');
  return candidates.some((c) => {
    if (!/^[0-9a-fA-F]{64}$/.test(c)) return false;
    try {
      return crypto.timingSafeEqual(Buffer.from(c.toLowerCase(), 'hex'), expectedBuf);
    } catch {
      return false;
    }
  });
}
