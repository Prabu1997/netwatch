// netwatch: live, session-based view of connections leaving this machine.
// Zero dependencies. Polls `ss`, enriches with /proc + rDNS, serves a dashboard over SSE.
const http = require('http');
const fs = require('fs');
const path = require('path');
const dns = require('dns').promises;
const { execFile } = require('child_process');
const intel = require('./intel');
const blocker = require('./block');

const PORT = +process.env.PORT || 8080;
const HOST = process.env.HOST || '127.0.0.1';
const POLL_MS = +process.env.POLL_MS || 2000;
const AUTOBLOCK = process.env.AUTOBLOCK === '1'; // opt-in: DROP outbound to any IP hit by a HIGH feed
const GONE_KEEP_MS = 5 * 60 * 1000;

const SHELLS = new Set(['sh', 'bash', 'dash', 'zsh', 'ash', 'ksh', 'fish', 'nc', 'ncat', 'netcat', 'socat', 'telnet']);
const COMMON_PORTS = new Set([22, 53, 80, 123, 143, 443, 465, 587, 853, 993, 995, 5228, 8080, 8443]);
const SUSPECT_DIRS = ['/tmp/', '/dev/shm/', '/var/tmp/', '/run/user/'];

const sessions = new Map(); // key -> session
const ipInfo = new Map();   // ip -> { host, owner }
let seq = 0;

const isPrivate = ip =>
  /^(10\.|127\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|::1$|fe80:|f[cd][0-9a-f]{2}:)/i.test(ip) || ip === '*' || ip === '0.0.0.0' || ip === '::';

function splitAddr(a) {
  a = a.replace(/%[^:\]]+/, ''); // strip %iface
  const i = a.lastIndexOf(':');
  return { ip: a.slice(0, i).replace(/^\[|\]$/g, ''), port: a.slice(i + 1) };
}

function runSS() {
  return new Promise(res => execFile('ss', ['-tunapH'], { maxBuffer: 16e6 }, (e, out) => res(e ? '' : out)));
}

function parseSS(out) {
  const rows = [];
  for (const line of out.split('\n')) {
    const f = line.trim().split(/\s+/);
    if (f.length < 6) continue;
    const [proto, state, , , local, remote] = f;
    const holders = [...line.matchAll(/\("([^"]*)",pid=(\d+)/g)].map(h => ({ name: h[1], pid: +h[2] }));
    // a socket can be shared by several processes (fork/exec): prefer a shell-like holder as the primary
    const m = holders.find(h => SHELLS.has(h.name)) || holders[0];
    const l = splitAddr(local), r = splitAddr(remote);
    rows.push({ proto, state, lip: l.ip, lport: +l.port || 0, rip: r.ip, rport: +r.port || 0,
      proc: m ? m.name : null, pid: m ? m.pid : null, holders: holders.map(h => h.name) });
  }
  return rows;
}

const procCache = new Map(); // pid -> {t, info}
function procInfo(pid) {
  if (!pid) return null;
  const c = procCache.get(pid);
  if (c && Date.now() - c.t < 30000) return c.info;
  const info = { exe: null, cmd: null, user: null, ppid: null, deleted: false };
  try { info.exe = fs.readlinkSync(`/proc/${pid}/exe`); } catch {}
  if (info.exe && info.exe.endsWith(' (deleted)')) { info.deleted = true; info.exe = info.exe.replace(' (deleted)', ''); }
  try { info.cmd = fs.readFileSync(`/proc/${pid}/cmdline`, 'utf8').replace(/\0/g, ' ').trim().slice(0, 200); } catch {}
  try {
    const s = fs.readFileSync(`/proc/${pid}/status`, 'utf8');
    info.ppid = +(s.match(/PPid:\s+(\d+)/) || [])[1] || null;
    const uid = (s.match(/Uid:\s+(\d+)/) || [])[1];
    info.user = uid;
    try {
      const pw = fs.readFileSync('/etc/passwd', 'utf8').split('\n').find(l => l.split(':')[2] === uid);
      if (pw) info.user = pw.split(':')[0];
    } catch {}
  } catch {}
  procCache.set(pid, { t: Date.now(), info });
  return info;
}

function enrich(ip) {
  if (isPrivate(ip) || ipInfo.has(ip)) return;
  const rec = { host: null, owner: null, asn: null, org: null, cc: null, cloud: false };
  ipInfo.set(ip, rec);
  intel.whoisAsn(ip).then(a => { if (a) { rec.asn = a.asn; rec.org = a.org; rec.cc = a.cc; rec.cloud = intel.isCloud(a.org); } }).catch(() => {});
  dns.reverse(ip).then(h => { rec.host = h[0]; }).catch(() => {});
}

function assess(s) {
  const flags = [];
  const p = s.p;
  const remoteExt = !isPrivate(s.rip);
  const established = s.state === 'ESTAB';
  if (s.state === 'LISTEN' || s.state === 'UNCONN') {
    if ((s.lip === '0.0.0.0' || s.lip === '::' || s.lip === '*') && s.state === 'LISTEN' && s.lport > 1024 && !COMMON_PORTS.has(s.lport))
      flags.push(['low', `Listening on all interfaces, port ${s.lport}`]);
    return flags;
  }
  if (!remoteExt) return flags;
  for (const f of intel.lookup(s.rip))
    flags.push([f.sev, `${f.sev === 'high' ? 'MALICIOUS IP' : 'Notice'}: ${f.name} (${f.cat})`, 'feed']);
  if (!s.pid && established) flags.push(['med', 'Unidentified process (no PID visible; run with root/--pid=host)']);
  if (p) {
    const base = p.exe ? path.basename(p.exe) : s.proc;
    const shell = SHELLS.has(base) ? base : (s.holders || []).find(h => SHELLS.has(h));
    if (shell && established)
      flags.push(['high', `Shell/netcat "${shell}" holds an external connection: possible reverse shell`]);
    if (p.deleted) flags.push(['high', 'Binary was deleted from disk while running']);
    if (p.exe && SUSPECT_DIRS.some(d => p.exe.startsWith(d)))
      flags.push(['high', `Executable runs from ${path.dirname(p.exe)}`]);
    if (p.user === 'root' && !p.exe) flags.push(['med', 'Root process with unreadable executable']);
  }
  if (!COMMON_PORTS.has(s.rport) && established)
    flags.push(['low', `Uncommon remote port ${s.rport}`]);
  return flags;
}

async function poll() {
  const now = Date.now();
  const rows = parseSS(await runSS());
  const seen = new Set();
  for (const r of rows) {
    if (r.state === 'UNCONN' && r.rip === '*') continue; // idle UDP sockets: noise
    const key = [r.proto, r.lip, r.lport, r.rip, r.rport, r.pid].join('|');
    seen.add(key);
    let s = sessions.get(key);
    if (!s) {
      s = { id: ++seq, ...r, first: now, status: 'active', events: [] };
      sessions.set(key, s);
      enrich(r.rip);
    }
    s.holders = r.holders; s.state = r.state; s.last = now; s.status = 'active'; s.gone = null;
    s.p = procInfo(r.pid);
  }
  for (const [key, s] of sessions) {
    if (!seen.has(key)) {
      if (s.status === 'active') { s.status = 'closed'; s.gone = now; }
      else if (now - s.gone > GONE_KEEP_MS) sessions.delete(key);
    }
  }
}

const alerted = new Set();
function logAlerts(list) {
  for (const x of list) {
    if (x.sev < 3 || alerted.has(x.id)) continue;
    alerted.add(x.id);
    if (AUTOBLOCK && x.flags.some(f => f[2] === 'feed' && f[0] === 'high'))
      blocker.block(x.rip, x.flags.map(f => f[1]).join('; ')).then(r => console.log(`autoblock ${x.rip}: ${r.ok ? 'DROP rule added' : r.err}`));
    const line = JSON.stringify({ t: new Date().toISOString(), proc: x.proc, pid: x.pid, user: x.user, remote: x.remote, blocked: AUTOBLOCK, asn: x.asn, org: x.org, flags: x.flags.map(f => f[1]) });
    try { fs.mkdirSync(intel.DATA_DIR, { recursive: true }); fs.appendFileSync(path.join(intel.DATA_DIR, 'alerts.jsonl'), line + '\n'); } catch {}
  }
}

function snapshot() {
  const list = [...sessions.values()].map(s => {
    const info = ipInfo.get(s.rip) || {};
    const flags = assess(s);
    const sev = flags.some(f => f[0] === 'high') ? 3 : flags.some(f => f[0] === 'med') ? 2 : flags.length ? 1 : 0;
    return { id: s.id, proto: s.proto, state: s.state, status: s.status, local: `${s.lip}:${s.lport}`,
      remote: s.rip === '*' ? '*' : `${s.rip}:${s.rport}`, rip: s.rip, host: info.host || null, asn: info.asn || null, org: info.org || null, cc: info.cc || null, cloud: !!info.cloud,
      external: !isPrivate(s.rip), blocked: blocker.isBlocked(s.rip), proc: s.proc, pid: s.pid, exe: s.p?.exe || null, cmd: s.p?.cmd || null,
      user: s.p?.user || null, first: s.first, last: s.last, flags, sev };
  });
  list.sort((a, b) => b.sev - a.sev || b.last - a.last);
  logAlerts(list);
  return { t: Date.now(), intel: intel.status(), block: { available: blocker.available(), error: blocker.error(), auto: AUTOBLOCK, list: blocker.list() }, sessions: list };
}

const clients = new Set();
const server = http.createServer((req, res) => {
  if (req.url === '/events') {
    res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive' });
    res.write(`data: ${JSON.stringify(snapshot())}\n\n`);
    clients.add(res);
    req.on('close', () => clients.delete(res));
  } else if (req.method === 'POST' && (req.url === '/api/block' || req.url === '/api/unblock')) {
    // custom header forces a CORS preflight, so other websites can't drive this endpoint
    const okHost = /^(127\.0\.0\.1|localhost)(:\d+)?$/.test(req.headers.host || '');
    if (req.headers['x-netwatch'] !== '1' || !okHost) { res.writeHead(403); return res.end('forbidden'); }
    let body = '';
    req.on('data', d => { body += d; if (body.length > 1e4) req.destroy(); });
    req.on('end', async () => {
      let ip; try { ip = JSON.parse(body).ip; } catch {}
      const r = ip ? await (req.url === '/api/block' ? blocker.block(ip, 'manual') : blocker.unblock(ip)) : { ok: false, err: 'missing ip' };
      res.writeHead(r.ok ? 200 : 400, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(r));
    });
  } else if (req.url === '/api/sessions') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(snapshot()));
  } else if (req.url === '/' || req.url === '/index.html') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(fs.readFileSync(path.join(__dirname, 'public', 'index.html')));
  } else { res.writeHead(404); res.end('not found'); }
});

(async function loop() {
  await poll().catch(e => console.error('poll failed', e));
  if (clients.size) { const d = `data: ${JSON.stringify(snapshot())}\n\n`; for (const c of clients) c.write(d); }
  setTimeout(loop, POLL_MS);
})();

intel.init();
blocker.init();
server.listen(PORT, HOST, () => console.log(`netwatch on http://${HOST}:${PORT}  `));
