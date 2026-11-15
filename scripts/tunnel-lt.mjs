// Public tunnel for the gatekeeper agent via localtunnel.me.
//
// Why not cloudflared: the VM's egress proxy BLOCKS api.trycloudflare.com
// (GET returns 403 "Your request was blocked"), so cloudflared quick
// tunnels cannot register from this VM. localtunnel.me IS reachable
// through the proxy, and its API lets us request a FIXED subdomain, so the
// public URL stays stable across restarts (unlike trycloudflare).
//
// How it works:
//   1. GET https://localtunnel.me/<subdomain> (via curl, which honors the
//      egress proxy) -> { port, url } for this subdomain.
//   2. A socat TCP forwarder listens on 127.0.0.1:<fwdPort> and forwards
//      each connection through the egress proxy (HTTP CONNECT, no auth
//      needed — verified) to localtunnel.me:<port> (the tunnel data plane).
//      This is needed because localtunnel's client opens a RAW TCP
//      connection, which cannot go through the proxy on its own.
//   3. Two localtunnel TunnelCluster instances connect to the forwarder
//      and pipe the remote HTTP requests to the local agent on <localPort>.
//      The tunnel port itself identifies the tunnel — no extra handshake.
//
// Usage: node scripts/tunnel-lt.mjs [subdomain] [localPort] [fwdPort]
//   subdomain defaults to "gatekeeper-fuziole"
//   localPort defaults to $PORT or 8788
//   fwdPort defaults to 18780
// Prints the public URL and keeps running until SIGTERM/SIGINT.
// No credentials are used or logged anywhere in this script.
import { spawn, execFile } from 'node:child_process';
import net from 'node:net';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const TunnelCluster = require('localtunnel/lib/TunnelCluster');

const SUBDOMAIN = process.argv[2] ?? 'gatekeeper-fuziole';
const LOCAL_PORT = Number(process.argv[3] ?? process.env.PORT ?? 8788);
const FWD_PORT = Number(process.argv[4] ?? 18780);

function log(...args) {
  console.log(new Date().toISOString(), '[tunnel]', ...args);
}

function proxyHostPort() {
  const raw = process.env.https_proxy ?? process.env.HTTPS_PROXY ?? process.env.http_proxy ?? '';
  try {
    const u = new URL(raw);
    return { host: u.hostname, port: Number(u.port) || 3128 };
  } catch {
    return { host: 'hatch-egress-proxy', port: 3128 };
  }
}

function getAssignment(subdomain) {
  return new Promise((resolve, reject) => {
    execFile(
      'curl',
      ['-s', '-m', '20', `https://localtunnel.me/${subdomain}`],
      (err, stdout) => {
        if (err) return reject(err);
        try {
          resolve(JSON.parse(stdout));
        } catch {
          reject(new Error(`bad API response: ${stdout.slice(0, 200)}`));
        }
      },
    );
  });
}

function waitForPort(port, timeoutMs = 10000) {
  const started = Date.now();
  return new Promise((resolve, reject) => {
    const tryOnce = () => {
      const s = net.connect({ host: '127.0.0.1', port });
      s.once('connect', () => {
        s.destroy();
        resolve();
      });
      s.once('error', () => {
        if (Date.now() - started > timeoutMs) return reject(new Error(`port ${port} never opened`));
        setTimeout(tryOnce, 250);
      });
    };
    tryOnce();
  });
}

const { host: proxyHost, port: proxyPort } = proxyHostPort();
log(`egress proxy: ${proxyHost}:${proxyPort} (no auth)`);

let assignment = await getAssignment(SUBDOMAIN);
if (!assignment?.url || !assignment?.port) {
  log(`subdomain ${SUBDOMAIN} unavailable (${JSON.stringify(assignment)}), falling back to a random one`);
  assignment = await getAssignment('?new');
}
if (!assignment?.url || !assignment?.port) {
  throw new Error(`localtunnel API gave no assignment: ${JSON.stringify(assignment)}`);
}
const { url: publicUrl, port: tunnelPort } = assignment;
log(`assigned ${publicUrl} (data plane localtunnel.me:${tunnelPort})`);

// socat forwarder: 127.0.0.1:FWD_PORT -> (proxy CONNECT) -> localtunnel.me:tunnelPort
const socat = spawn('socat', [
  `TCP-LISTEN:${FWD_PORT},bind=127.0.0.1,fork,reuseaddr`,
  `PROXY:${proxyHost}:localtunnel.me:${tunnelPort},proxyport=${proxyPort}`,
], { stdio: 'ignore' });
socat.on('error', (err) => {
  log('socat failed to start:', err.message);
  process.exit(1);
});
socat.on('exit', (code) => {
  log(`socat exited (code ${code}) — tunnel is down`);
  process.exit(1);
});
await waitForPort(FWD_PORT);
log(`forwarder up on 127.0.0.1:${FWD_PORT}`);

let shuttingDown = false;
let openClusters = 0;
function openCluster(n) {
  if (shuttingDown) return;
  const cluster = new TunnelCluster({
    remote_host: '127.0.0.1',
    remote_port: FWD_PORT,
    local_host: '127.0.0.1',
    local_port: LOCAL_PORT,
  });
  cluster.on('open', () => {
    openClusters += 1;
    log(`data connection #${n} open (total open: ${openClusters})`);
  });
  cluster.on('dead', () => {
    openClusters = Math.max(0, openClusters - 1);
    log(`data connection #${n} died — reopening in 1s`);
    setTimeout(() => openCluster(n), 1000);
  });
  cluster.on('error', (err) => {
    log(`data connection #${n} error: ${err?.message ?? err}`);
  });
  cluster.open();
}

openCluster(1);
openCluster(2);

console.log('');
console.log(`PUBLIC ENDPOINT (register this in the Agent Games dashboard):`);
console.log(`  ${publicUrl}/agent`);
console.log(`  health: ${publicUrl}/health`);
console.log('');

function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  log(`received ${signal} — shutting down`);
  try {
    socat.kill('SIGTERM');
  } catch {
    /* already gone */
  }
  setTimeout(() => process.exit(0), 1000).unref();
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
