#!/usr/bin/env bash
# Start/stop the Proof Gatekeeper agent + its public tunnel.
#   scripts/start.sh        start server + cloudflared quick tunnel, print public URL
#   scripts/start.sh stop   stop both
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
mkdir -p logs data

SERVER_LOG="$ROOT/logs/server.log"
TUNNEL_LOG="$ROOT/logs/tunnel.log"

stop_all() {
  pkill -f "node src/server.mjs" 2>/dev/null || true
  pkill -f "node scripts/tunnel-lt.mjs" 2>/dev/null || true
  pkill -f "TCP-LISTEN:18780" 2>/dev/null || true
  sleep 1
}

if [[ "${1:-}" == "stop" ]]; then
  stop_all
  echo "gatekeeper stopped"
  exit 0
fi

# Load .env if present (secret lives there / in the environment).
if [[ -f .env ]]; then
  set -a; source .env; set +a
fi
export PORT="${PORT:-8788}" HOST="${HOST:-127.0.0.1}"

if [[ -z "${AGENT_GAMES_HMAC_SECRET:-}" ]]; then
  echo "WARNING: AGENT_GAMES_HMAC_SECRET is not set — server will run in DEV mode"
  echo "(unsigned requests accepted). Set the secret from the dashboard (Rotate"
  echo "Secret), put it in .env, and restart before registering the endpoint."
fi

stop_all

# 1. Agent server
nohup node src/server.mjs >>"$SERVER_LOG" 2>&1 &
echo "server started (pid $!, log $SERVER_LOG)"
for i in $(seq 1 30); do
  if curl -fsS -o /dev/null "http://127.0.0.1:${PORT}/health" 2>/dev/null; then break; fi
  sleep 1
done
curl -fsS "http://127.0.0.1:${PORT}/health" >/dev/null || { echo "server did not come up — see $SERVER_LOG"; exit 1; }
echo "server healthy on http://127.0.0.1:${PORT}"

# 2. Public tunnel (localtunnel.me, fixed subdomain — see scripts/tunnel-lt.mjs
#    for why cloudflared cannot be used from this VM: the egress proxy blocks
#    api.trycloudflare.com). The subdomain is stable across restarts, so the
#    registered endpoint URL does not change when the tunnel is restarted.
nohup node scripts/tunnel-lt.mjs "${TUNNEL_SUBDOMAIN:-gatekeeper-fuziole}" "${PORT}" >>"$TUNNEL_LOG" 2>&1 &
echo "tunnel started (log $TUNNEL_LOG)"

URL=""
for i in $(seq 1 60); do
  URL=$(grep -oE "https://[a-z0-9-]+\.loca\.lt" "$TUNNEL_LOG" | head -1 || true)
  [[ -n "$URL" ]] && break
  sleep 1
done
if [[ -z "$URL" ]]; then
  echo "tunnel URL not found after 60s — see $TUNNEL_LOG"
  exit 1
fi

# 3. Verify from the outside, through the tunnel (curl goes via the proxy
#    to localtunnel's edge, back through the tunnel to the local server).
#    localtunnel shows a one-time reminder page for browser visits; curl
#    with a plain UA gets the real response. Retry a few times while the
#    data connections establish.
ok=0
for i in $(seq 1 12); do
  if curl -fsS -A "gatekeeper-healthcheck" "$URL/health" >/dev/null 2>&1 && \
     curl -fsS -A "gatekeeper-healthcheck" "$URL/agent" >/dev/null 2>&1; then
    ok=1; break
  fi
  sleep 2
done
if [[ "$ok" == "1" ]]; then
  echo ""
  echo "PUBLIC ENDPOINT (register this in the Agent Games dashboard):"
  echo "  $URL/agent"
  echo ""
  echo "Verified from outside: GET $URL/health and GET $URL/agent both 200."
  echo "NOTE: the subdomain is fixed (gatekeeper-fuziole), so this URL survives"
  echo "tunnel restarts — but the tunnel + server must be running during rounds."
else
  echo ""
  echo "WARNING: public URL $URL did not answer health checks — see $TUNNEL_LOG"
  echo "The tunnel driver will be stopped (leaving it running only burns the"
  echo "shared egress IP's rate limit at localtunnel.me)."
  pkill -f "node scripts/tunnel-lt.mjs" 2>/dev/null || true
  pkill -f "TCP-LISTEN:18780" 2>/dev/null || true
  echo ""
  echo "KNOWN BLOCKER (2026-11-15): this VM has no direct egress — all traffic"
  echo "goes through an HTTP egress proxy that (a) BLOCKS api.trycloudflare.com"
  echo "(403), so cloudflared quick tunnels cannot register, and (b) blackholes"
  echo "CONNECT to non-443 ports (verified: no SSH banner from github.com:22),"
  echo "so localtunnel's raw-TCP data plane can never connect (edge: 503)."
  echo "The agent itself is fully working locally (npm test: 17/17)."
  echo ""
  echo "To get a public endpoint, one of these is needed (see README):"
  echo "  1. Cloudflare account + API token -> named tunnel (api.cloudflare.com"
  echo "     is reachable) + cloudflared --protocol http2"
  echo "  2. ngrok authtoken (free signup; ngrok honors HTTPS_PROXY)"
  echo "  3. Tailscale Funnel (controlplane.tailscale.com is reachable)"
  echo "  4. Run the agent on a host with direct egress (user machine / VPS)"
  exit 1
fi
