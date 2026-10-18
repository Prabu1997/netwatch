// Blocking via a dedicated iptables chain (NETWATCH, hooked into OUTPUT). Undo everything with:
//   iptables -D OUTPUT -j NETWATCH; iptables -F NETWATCH; iptables -X NETWATCH   (same for ip6tables)
const { execFile } = require('child_process');
const fs = require('fs');
const path = require('path');
const net = require('net');
const intel = require('../../intel');

const FILE = path.join(intel.DATA_DIR, 'blocked.json');
const CHAIN = 'NETWATCH';
const blocked = new Map(); // ip -> {at, reason}
let ready = false, lastError = null;

const bin = ip => (net.isIPv6(ip) ? 'ip6tables' : 'iptables');
const run = (cmd, args) => new Promise(res => execFile(cmd, args, (e, o, err) => res({ ok: !e, err: (err || (e && e.message) || '').trim() })));
const isProtected = ip => /^(10\.|127\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|::1$|fe80:|f[cd][0-9a-f]{2}:|0\.0\.0\.0|::$)/i.test(ip) || !net.isIP(ip);

async function setupChain() {
  for (const cmd of ['iptables', 'ip6tables']) {
    await run(cmd, ['-N', CHAIN]);
    const chk = await run(cmd, ['-C', 'OUTPUT', '-j', CHAIN]);
    if (!chk.ok) {
      const r = await run(cmd, ['-I', 'OUTPUT', '1', '-j', CHAIN]);
      if (!r.ok) { lastError = `${cmd}: ${r.err}`; return false; }
    }
  }
  return true;
}

async function init(log = console.log) {
  ready = await setupChain();
  if (!ready) return log('blocking unavailable: ' + lastError + ' (needs --cap-add NET_ADMIN)');
  let saved = {};
  try { saved = JSON.parse(fs.readFileSync(FILE, 'utf8')); } catch {}
  for (const [ip, v] of Object.entries(saved)) { blocked.set(ip, v); await add(ip); }
  log(`blocking ready, ${blocked.size} rule(s) restored`);
}

async function add(ip) {
  const c = await run(bin(ip), ['-C', CHAIN, '-d', ip, '-j', 'DROP']);
  if (c.ok) return { ok: true };
  return run(bin(ip), ['-A', CHAIN, '-d', ip, '-j', 'DROP']);
}

const persist = () => { try { fs.mkdirSync(intel.DATA_DIR, { recursive: true }); fs.writeFileSync(FILE, JSON.stringify(Object.fromEntries(blocked))); } catch {} };

async function block(ip, reason) {
  if (isProtected(ip)) return { ok: false, err: 'refusing to block private/local address' };
  if (!ready) return { ok: false, err: 'blocking unavailable: ' + lastError };
  if (blocked.has(ip)) return { ok: true };
  const r = await add(ip);
  if (r.ok) { blocked.set(ip, { at: Date.now(), reason }); persist(); }
  return r;
}

async function unblock(ip) {
  if (!net.isIP(ip)) return { ok: false, err: 'bad ip' };
  const r = await run(bin(ip), ['-D', CHAIN, '-d', ip, '-j', 'DROP']);
  blocked.delete(ip); persist();
  return { ok: true, err: r.ok ? '' : r.err };
}

module.exports = { init, block, unblock, isBlocked: ip => blocked.has(ip), list: () => Object.fromEntries(blocked), available: () => ready, error: () => lastError };
