// macOS enforcement via pf. Rules live in the "netwatch" anchor; the anchor is hooked into the main ruleset by
// loading /etc/pf.conf plus one `anchor "netwatch"` line. Needs root. Undo everything with: sudo pfctl -f /etc/pf.conf
// (the persisted block list is re-applied on the next start).
const { execFile } = require('child_process');
const fs = require('fs');
const path = require('path');
const net = require('net');
const intel = require('../../intel');

const FILE = path.join(intel.DATA_DIR, 'blocked.json');
const ANCHOR = 'netwatch';
const blocked = new Map();
let ready = false, lastError = null;

const isProtected = ip => /^(10\.|127\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|::1$|fe80:|f[cd][0-9a-f]{2}:|0\.0\.0\.0|::$)/i.test(ip) || !net.isIP(ip);

function run(args, input) {
  return new Promise(res => {
    const p = execFile('pfctl', args, (e, o, err) => res({ ok: !e, out: o, err: (err || (e && e.message) || '').trim() }));
    if (input != null) p.stdin.end(input);
  });
}

// Pure: the anchor ruleset for a set of blocked IPs.
function rules(ips) {
  const list = [...ips];
  if (!list.length) return '';
  return `table <netwatch_blocked> persist { ${list.join(', ')} }\nblock drop out quick to <netwatch_blocked>\n`;
}

const MAIN = base => (base.includes(`anchor "${ANCHOR}"`) ? base : base.replace(/\s*$/, '\n') + `anchor "${ANCHOR}"\n`);

async function apply() {
  return run(['-a', ANCHOR, '-f', '-'], rules(blocked.keys()));
}

async function init(log = console.log) {
  if (process.getuid && process.getuid() !== 0) {
    lastError = 'pf needs root: run with sudo';
    return log('blocking unavailable: ' + lastError);
  }
  try {
    const main = MAIN(fs.readFileSync('/etc/pf.conf', 'utf8'));
    const r = await run(['-f', '-'], main);
    if (!r.ok) throw new Error(r.err);
    await run(['-e']); // enable; harmless if already enabled
  } catch (e) { lastError = String(e.message || e); return log('blocking unavailable: ' + lastError); }
  ready = true;
  let saved = {};
  try { saved = JSON.parse(fs.readFileSync(FILE, 'utf8')); } catch {}
  for (const [ip, v] of Object.entries(saved)) blocked.set(ip, v);
  await apply();
  log(`blocking ready (pf), ${blocked.size} rule(s) restored`);
}

const persist = () => { try { fs.mkdirSync(intel.DATA_DIR, { recursive: true }); fs.writeFileSync(FILE, JSON.stringify(Object.fromEntries(blocked))); } catch {} };

async function block(ip, reason) {
  if (isProtected(ip)) return { ok: false, err: 'refusing to block private/local address' };
  if (!ready) return { ok: false, err: 'blocking unavailable: ' + lastError };
  if (blocked.has(ip)) return { ok: true };
  blocked.set(ip, { at: Date.now(), reason });
  const r = await apply();
  if (!r.ok) { blocked.delete(ip); return { ok: false, err: r.err }; }
  // pf keeps existing states alive past a new `quick` rule, so kill them or running connections/pings carry on
  await run(['-k', net.isIPv6(ip) ? '::/0' : '0.0.0.0/0', '-k', ip]);
  persist();
  return { ok: true };
}

async function unblock(ip) {
  if (!net.isIP(ip)) return { ok: false, err: 'bad ip' };
  blocked.delete(ip);
  const r = await apply();
  persist();
  return { ok: true, err: r.ok ? '' : r.err };
}

module.exports = { rules, MAIN, init, block, unblock, isBlocked: ip => blocked.has(ip), list: () => Object.fromEntries(blocked), available: () => ready, error: () => lastError };
