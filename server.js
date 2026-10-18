// netwatch: live, session-based view of connections leaving this machine.
// Zero dependencies. Polls `ss`, enriches with /proc + rDNS, serves a dashboard over SSE.
const http = require('http');
const fs = require('fs');
const path = require('path');
const dns = require('dns').promises;
const { execFile } = require('child_process');
const intel = require('./intel');
const blocker = require('./lib/enforce');
const platform = require('./lib/platform');
const policy = require('./lib/policy');
const { FlowTable, startCapture, connKey } = require('./lib/flows');
const { packetOnly } = require('./lib/sessionmerge');
const { classify } = require('./lib/appid');
const anomaly = require('./lib/anomaly');
const store = require('./lib/store');
const auth = require('./lib/auth');
const { DomainList } = require('./lib/domains');
const domainfeed = require('./lib/domainfeed');
const { DnsFilter } = require('./lib/dnsfilter');
const resolvers = require('./lib/resolvers');
const trust = require('./lib/trust');
const { Baseline } = require('./lib/baseline');

const PORT = +process.env.PORT || 8080;
const HOST = process.env.HOST || '127.0.0.1';
const POLL_MS = +process.env.POLL_MS || 2000;
const AUTOBLOCK = process.env.AUTOBLOCK === '1'; // opt-in: DROP outbound to any IP hit by a HIGH feed
const ENFORCE = process.env.ENFORCE === '1';     // opt-in: block destinations that a policy "deny" rule matches
const CAPTURE = process.env.CAPTURE !== '0';     // App-ID packet capture (needs root); falls back to port/process only
const POLICY_FILE = path.join(intel.DATA_DIR, 'policy.json');
const DNS_FILTER = process.env.DNS_FILTER === '1';       // opt-in local DNS filtering proxy (port 53 needs root)
const DNS_PORT = process.env.DNS_PORT != null ? +process.env.DNS_PORT : 53;
const DNS_HOST = process.env.DNS_HOST || '127.0.0.1';
const BASELINE_FILE =path.join(intel.DATA_DIR, 'baseline.json');
const LEARN_MIN = process.env.BASELINE_LEARN_MIN != null ? +process.env.BASELINE_LEARN_MIN : 10; // quiet period before "first contact" flags
const GONE_KEEP_MS = 5 * 60 * 1000;

const SHELLS = platform.SHELLS;
const COMMON_PORTS = new Set([22, 53, 80, 123, 143, 443, 465, 587, 853, 993, 995, 5228, 8080, 8443]);
const SUSPECT_DIRS = ['/tmp/', '/dev/shm/', '/var/tmp/', '/run/user/'];

const sessions = new Map(); // key -> session
const ipInfo = new Map();   // ip -> { host, owner }
let seq = 0;

const isPrivate = ip =>
  /^(10\.|127\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|::1$|fe80:|f[cd][0-9a-f]{2}:)/i.test(ip) || ip === '*' || ip === '0.0.0.0' || ip === '::';

const procCache = new Map(); // pid -> {t, info}
async function procInfo(pid) {
  if (!pid) return null;
  const c = procCache.get(pid);
  if (c && Date.now() - c.t < 30000) return c.info;
  const info = await platform.procInfo(pid);
  procCache.set(pid, { t: Date.now(), info });
  return info;
}

const flows = new FlowTable();
const baseline = Baseline.load(BASELINE_FILE, { learnMs: LEARN_MIN * 60 * 1000 });

// ---- domain blocking: lists + policy rules with a "domain" field ----
const domains = new DomainList();
const recentDns = [];                // newest last, bounded
const dnsLogged = new Map();         // name -> last time it was written to alerts.jsonl (don't spam on retries)
let dnsFilter = null;
let upstreamList = [];
const refreshUpstreams = () => {
  const env = (process.env.DNS_UPSTREAM || '').split(',').map(s => s.trim()).filter(Boolean);
  const found = env.length ? env : resolvers.forwardable(resolvers.systemResolvers());
  if (found.length) upstreamList = found;
};

function dnsDecide(name) {
  const hit = domains.match(name);
  if (hit) return { action: 'deny', why: `${hit.list}: ${hit.domain}` };
  const dr = rules.filter(r => r.domain);
  if (dr.length) {
    const v = policy.evaluate(dr, { domain: name, app: 'dns', proto: 'udp', external: true, feeds: [] });
    if (v.action !== 'allow') return { action: v.action, why: `policy "${v.rule}"` };
  }
  return { action: 'allow' };
}

function onDnsDecision(d) {
  recentDns.push(d); if (recentDns.length > 200) recentDns.shift();
  if (d.action === 'allow') return;
  if (Date.now() - (dnsLogged.get(d.name) || 0) < 60000) return;
  dnsLogged.set(d.name, d.t); if (dnsLogged.size > 2000) dnsLogged.clear();
  console.log(`dns ${d.action}: ${d.name} (${d.why})`);
  store.append(path.join(intel.DATA_DIR, 'alerts.jsonl'), JSON.stringify({ t: new Date(d.t).toISOString(), kind: 'dns', name: d.name, action: d.action, why: d.why, client: d.from }) + '\n');
}
let capture = { running: false, error: 'disabled', packets: 0 };
let rules = [], rulesError = null;
function loadRules() {
  // store.read() refuses a policy file that someone else could have edited; the last good rulebase stays in force.
  const t = trust.check(POLICY_FILE);
  if (!t.ok) { rulesError = 'policy.json not trusted: ' + t.reason; return; }
  if (t.missing) { rules = []; rulesError = null; return; }
  try {
    const r = JSON.parse(store.read(POLICY_FILE));
    const errs = policy.validate(r);
    if (errs.length) { rulesError = errs.join('; '); return; } // keep the last good rulebase
    rules = r; rulesError = null;
  } catch (e) { rulesError = String(e.message); }
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
  const rows = await platform.connections();
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
    s.p = await procInfo(r.pid);
    checkBaseline(s, now);
  }
  // Flows the capture saw that the socket list did not: short-lived connections and unconnected UDP (QUIC).
  const known = new Set();
  for (const s of sessions.values()) if (s.origin !== 'packet') known.add(connKey(s.proto, s.lip, s.lport, s.rip, s.rport));
  for (const m of packetOnly(flows.conns, rows, now, { known })) {
    let s = sessions.get(m.key);
    if (!s) {
      if (!m.live) continue; // quiet flow whose row was already aged out: don't resurrect it
      const o = m.owner, c = m.rec;
      s = { id: ++seq, proto: c.proto, state: 'SEEN', lip: c.lip, lport: c.lport, rip: c.rip, rport: c.rport,
        proc: o ? o.proc : null, pid: o ? o.pid : null, holders: o ? o.holders : [], first: c.first, status: 'active', events: [], origin: 'packet' };
      sessions.set(m.key, s);
      enrich(c.rip);
      s.p = await procInfo(s.pid);
    }
    s.pkts = m.rec.pktsOut + m.rec.pktsIn; s.bytes = m.rec.bytesOut + m.rec.bytesIn;
    if (m.live) { seen.add(m.key); s.status = 'active'; s.gone = null; s.last = now; checkBaseline(s, now); }
  }
  for (const [key, s] of sessions) {
    if (!seen.has(key)) {
      if (s.status === 'active') { s.status = 'closed'; s.gone = now; }
      else if (now - s.gone > GONE_KEEP_MS) sessions.delete(key);
    }
  }
}

// Once per session: has this program ever talked to this destination before? Waits a few seconds for the
// hostname (SNI) to be captured, since a name is a steadier identity than a CDN address.
function checkBaseline(s, now) {
  if (s.baselined || (s.state !== 'ESTAB' && s.state !== 'SEEN') || isPrivate(s.rip) || !s.proc) return;
  const fl = flows.get(s.proto, s.lip, s.lport, s.rip, s.rport) || {};
  const name = fl.sni || fl.host || flows.nameFor(s.rip);
  if (!name && now - s.first < 4000) return;
  s.baselined = true;
  s.destKey = name || s.rip;
  s.newDest = baseline.observe(anomaly.normProc(s.p?.exe || s.proc), s.destKey, now) === 'new';
}

const alerted = new Set();
function logAlerts(list) {
  for (const x of list) {
    if (x.sev < 3 || alerted.has(x.id)) continue;
    alerted.add(x.id);
    if ((AUTOBLOCK && x.flags.some(f => f[2] === 'feed' && f[0] === 'high')) || (ENFORCE && x.policy?.action === 'deny' && !x.policy.byDomain))
      blocker.block(x.rip, x.flags.map(f => f[1]).join('; ')).then(r => console.log(`autoblock ${x.rip}: ${r.ok ? 'DROP rule added' : r.err}`));
    const line = JSON.stringify({ t: new Date().toISOString(), proc: x.proc, pid: x.pid, user: x.user, remote: x.remote, blocked: AUTOBLOCK, asn: x.asn, org: x.org, flags: x.flags.map(f => f[1]) });
    store.append(path.join(intel.DATA_DIR, 'alerts.jsonl'), line + '\n');
  }
}

// App-ID from captured payload when available, otherwise from port (and the hostname we saw for this IP).
function classifyFallback(s, fl) {
  if (fl.app) return { app: fl.app, via: fl.via };
  const name = flows.nameFor(s.rip);
  return classify({ sni: name, proto: s.proto, rport: s.rport });
}

function snapshot() {
  const list = [...sessions.values()].map(s => {
    const info = ipInfo.get(s.rip) || {};
    const flags = assess(s);
    const fl = flows.get(s.proto, s.lip, s.lport, s.rip, s.rport) || {};
    const ext = !isPrivate(s.rip);
    flags.push(...anomaly.protocolMismatch(fl, s));
    if (s.newDest && anomaly.isRisky(s.proc)) flags.push(['med', `First contact: "${s.proc}" has never connected to ${s.destKey} before`, 'baseline']);
    const id = classifyFallback(s, fl);
    const name = fl.sni || fl.host || flows.nameFor(s.rip);
    const dh = ext && name ? domains.match(name) : null; // a client that skipped our DNS (cached IP, DoH) still gives its name away in the handshake
    if (dh) flags.push(['high', `Blocked domain: ${dh.domain} (${dh.list})`, 'domain']);
    const verdict = ext && s.state !== 'LISTEN' && s.state !== 'UNCONN'
      ? policy.evaluate(rules, { proto: s.proto, app: id.app, proc: s.proc, user: s.p?.user, rip: s.rip, rport: s.rport, cc: info.cc, external: ext,
        feeds: intel.lookup(s.rip).map(f => f.id), domain: name })
      : { action: 'allow', rule: 'n/a', index: -1 };
    verdict.byDomain = verdict.index >= 0 && !!rules[verdict.index].domain; // a name rule must not black-hole a shared CDN address
    if (verdict.action !== 'allow') flags.push([verdict.action === 'deny' ? 'high' : 'med', `Policy "${verdict.rule}": ${verdict.action}`, 'policy']);
    const sev = flags.some(f => f[0] === 'high') ? 3 : flags.some(f => f[0] === 'med') ? 2 : flags.length ? 1 : 0;
    return { id: s.id, origin: s.origin || 'socket', pkts: s.pkts || 0, bytes: s.bytes || 0, app: id.app, appVia: id.via, sni: fl.sni || fl.host || flows.nameFor(s.rip), ja3: fl.ja3 || null, policy: verdict, proto: s.proto, state: s.state, status: s.status, local: `${s.lip}:${s.lport}`,
      remote: s.rip === '*' ? '*' : `${s.rip}:${s.rport}`, rip: s.rip, host: info.host || null, asn: info.asn || null, org: info.org || null, cc: info.cc || null, cloud: !!info.cloud,
      external: !isPrivate(s.rip), blocked: blocker.isBlocked(s.rip), proc: s.proc, pid: s.pid, exe: s.p?.exe || null, cmd: s.p?.cmd || null,
      user: s.p?.user || null, first: s.first, last: s.last, flags, sev };
  });
  list.sort((a, b) => b.sev - a.sev || b.last - a.last);
  logAlerts(list);
  return { t: Date.now(), platform: platform.name, capture: { running: capture.running, error: capture.error, packets: capture.packets },
    policy: { rules: rules.length, error: rulesError, enforce: ENFORCE },
    baseline: { learning: baseline.learning(), until: baseline.learnUntil, procs: baseline.procs.size },
    integrity: trust.problems(),
    dns: { enabled: DNS_FILTER, listening: !!(dnsFilter && dnsFilter.port), port: dnsFilter ? dnsFilter.port : null, error: dnsFilter ? dnsFilter.error : null,
      upstreams: upstreamList.length, stats: dnsFilter ? dnsFilter.stats : null, domains: domains.size(), recent: recentDns.slice(-15) },
    intel: intel.status(), block: { available: blocker.available(), error: blocker.error(), auto: AUTOBLOCK, list: blocker.list() }, sessions: list };
}

// API token: every route except the static page needs it. Persisted (0600) so a restart doesn't log you out;
// NETWATCH_TOKEN overrides. The page itself holds no data, so serving it without a token leaks nothing.
const TOKEN_FILE = path.join(intel.DATA_DIR, 'api-token');
const ALLOW_REMOTE = process.env.ALLOW_REMOTE === '1';
let TOKEN = process.env.NETWATCH_TOKEN || (store.read(TOKEN_FILE) || '').trim();
if (TOKEN.length < 20) { TOKEN = auth.newToken(); if (!process.env.NETWATCH_TOKEN) store.write(TOKEN_FILE, TOKEN + '\n', 0o600); }
const mutationAllowed = auth.limiter(20, 60000);
const send = (res, code, obj) => { res.writeHead(code, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }); res.end(JSON.stringify(obj)); };

const clients = new Set();
const server = http.createServer((req, res) => {
  const pathname = new URL(req.url, 'http://x').pathname;
  const isPage = req.method === 'GET' && (pathname === '/' || pathname === '/index.html');
  const mutating = req.method === 'POST';
  const a = auth.authorize(req, { token: TOKEN, allowRemote: ALLOW_REMOTE, mutating, public: isPage });
  if (!a.ok) return send(res, a.status, { ok: false, err: a.why });

  if (isPage) {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', 'X-Frame-Options': 'DENY', 'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer', 'Content-Security-Policy': "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'" });
    return res.end(fs.readFileSync(path.join(__dirname, 'public', 'index.html')));
  }
  if (pathname === '/api/ping') return send(res, 200, { ok: true });
  if (pathname === '/events') {
    res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive' });
    res.write(`data: ${JSON.stringify(snapshot())}\n\n`);
    clients.add(res);
    req.on('close', () => clients.delete(res));
  } else if (mutating && (pathname === '/api/block' || pathname === '/api/unblock')) {
    if (!mutationAllowed()) return send(res, 429, { ok: false, err: 'too many block/unblock requests; wait a minute' });
    let body = '';
    req.on('data', d => { body += d; if (body.length > 1e4) req.destroy(); });
    req.on('end', async () => {
      let ip; try { ip = JSON.parse(body).ip; } catch {}
      const r = ip ? await (pathname === '/api/block' ? blocker.block(ip, 'manual') : blocker.unblock(ip)) : { ok: false, err: 'missing ip' };
      send(res, r.ok ? 200 : 400, r);
    });
  } else if (pathname === '/api/sessions') {
    send(res, 200, snapshot());
  } else send(res, 404, { ok: false, err: 'not found' });
});

(async function loop() {
  await poll().catch(e => console.error('poll failed', e));
  if (clients.size) { const d = `data: ${JSON.stringify(snapshot())}\n\n`; for (const c of clients) c.write(d); }
  setTimeout(loop, POLL_MS);
})();

intel.init();
blocker.init();
loadRules();
domainfeed.init(domains, intel.DATA_DIR);
if (DNS_FILTER) {
  refreshUpstreams();
  setInterval(refreshUpstreams, 60000).unref();
  dnsFilter = new DnsFilter({ decide: dnsDecide, upstreams: () => upstreamList, onDecision: onDnsDecision });
  dnsFilter.start(DNS_PORT, DNS_HOST).then(ok => {
    if (!ok) return;
    console.log(`dns filter on ${DNS_HOST}:${dnsFilter.port}, upstream: ${upstreamList.join(', ') || 'NONE (set DNS_UPSTREAM=ip,ip)'}`);
  });
}
setInterval(() => baseline.save(BASELINE_FILE), 30000).unref();
process.on('SIGINT', () => { baseline.save(BASELINE_FILE); process.exit(0); });
process.on('SIGTERM', () => { baseline.save(BASELINE_FILE); process.exit(0); });
fs.watchFile(POLICY_FILE, { interval: 2000 }, loadRules);
if (CAPTURE) capture = startCapture(flows, platform);
server.listen(PORT, HOST, () => console.log(`netwatch on http://${HOST}:${PORT}\nopen this link once (it stores the access token in your browser):\n  http://${HOST}:${PORT}/#t=${TOKEN}`));
