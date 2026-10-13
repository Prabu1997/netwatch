// Threat intel: downloads public IP blocklists (on start, then daily), matches IPs/CIDRs against them,
// and resolves ASN + owner via Team Cymru DNS. A feed hit is judged on the IP itself, never on who owns it:
// an AWS/Azure address on abuse.ch's C2 list is still flagged.
const fs = require('fs');
const path = require('path');
const dns = require('dns').promises;

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const CACHE = path.join(DATA_DIR, 'feeds.json');
const DAY = 24 * 3600 * 1000;

// sev: high = known-bad infrastructure, med = context worth a look
const FEEDS = [
  { id: 'feodo',   name: 'abuse.ch Feodo C2',      sev: 'high', cat: 'botnet C2',            url: 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt' },
  { id: 'et',      name: 'Emerging Threats block', sev: 'high', cat: 'compromised/attacker',  url: 'https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt' },
  { id: 'drop',    name: 'Spamhaus DROP',          sev: 'high', cat: 'hijacked/criminal net', url: 'https://www.spamhaus.org/drop/drop_v4.json' },
  { id: 'ipsum',   name: 'IPsum (3+ lists)',       sev: 'high', cat: 'multi-list malicious',  url: 'https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt' },
  { id: 'custom',  name: 'Custom list (data/custom.txt)', sev: 'high', cat: 'user-defined', url: null },
  { id: 'tor',     name: 'Tor exit nodes',         sev: 'med',  cat: 'anonymiser exit',       url: 'https://check.torproject.org/torbulkexitlist' },
];

const ipToInt = ip => ip.split('.').reduce((a, o) => (a * 256 + +o), 0);
const isV4 = ip => /^\d{1,3}(\.\d{1,3}){3}$/.test(ip);

let lastParsed = {};
let exact = new Map();  // ip -> [feed ids]
let cidrs = [];         // [{net, mask, feed}]
let status = { feeds: {}, updated: null, loading: false };
const hitCache = new Map();

function parse(feed, text) {
  const ips = [], nets = [];
  for (const line of text.split('\n')) {
    if (!line.trim() || line.startsWith('#') || line.startsWith(';')) continue;
    const m = line.match(/(\d{1,3}(?:\.\d{1,3}){3})(?:\/(\d{1,2}))?/);
    if (!m) continue;
    if (m[2] && +m[2] < 32) nets.push({ net: ipToInt(m[1]), bits: +m[2], feed: feed.id });
    else ips.push(m[1]);
  }
  return { ips, nets };
}

const CUSTOM = path.join(DATA_DIR, 'custom.txt'); // one IP/CIDR per line: your own blocklist, also handy for testing
function loadCustom() { try { return parse({ id: 'custom' }, fs.readFileSync(CUSTOM, 'utf8')); } catch { return { ips: [], nets: [] }; } }

function index(parsed) { // parsed: { feedId: {ips, nets} }
  lastParsed = parsed;
  parsed = { ...parsed, custom: loadCustom() };
  const e = new Map(); const c = [];
  for (const [id, p] of Object.entries(parsed)) {
    for (const ip of p.ips) { const a = e.get(ip); if (a) a.push(id); else e.set(ip, [id]); }
    c.push(...p.nets);
  }
  exact = e; cidrs = c; hitCache.clear();
}

async function refresh(log = console.log) {
  status.loading = true;
  const parsed = {};
  await Promise.all(FEEDS.filter(f => f.url).map(async f => {
    try {
      const r = await fetch(f.url, { signal: AbortSignal.timeout(30000), headers: { 'User-Agent': 'netwatch-local/1.0' } });
      if (!r.ok) throw new Error('HTTP ' + r.status);
      const p = parse(f, await r.text());
      if (!p.ips.length && !p.nets.length) throw new Error('empty feed');
      parsed[f.id] = p;
      status.feeds[f.id] = { ok: true, count: p.ips.length + p.nets.length, at: Date.now() };
    } catch (e) {
      status.feeds[f.id] = { ok: false, error: String(e.message || e), count: status.feeds[f.id]?.count || 0, at: status.feeds[f.id]?.at || null };
      log(`feed ${f.id} failed: ${e.message}`);
    }
  }));
  // keep previously cached data for feeds that failed today
  let old = {};
  try { old = JSON.parse(fs.readFileSync(CACHE, 'utf8')).parsed || {}; } catch {}
  for (const f of FEEDS.filter(f => f.url)) if (!parsed[f.id] && old[f.id]) parsed[f.id] = old[f.id];
  if (Object.keys(parsed).length) {
    index(parsed);
    status.updated = Date.now();
    try { fs.mkdirSync(DATA_DIR, { recursive: true }); fs.writeFileSync(CACHE, JSON.stringify({ updated: status.updated, status: status.feeds, parsed })); } catch (e) { log('cache write failed: ' + e.message); }
  }
  status.loading = false;
  log(`threat feeds loaded: ${exact.size} IPs, ${cidrs.length} CIDRs`);
}

function init(log = console.log) {
  let age = Infinity;
  try {
    const c = JSON.parse(fs.readFileSync(CACHE, 'utf8'));
    index(c.parsed); status.feeds = Object.fromEntries(Object.entries(c.status || {}).filter(([k]) => FEEDS.some(f => f.id === k && f.url))); status.updated = c.updated; age = Date.now() - c.updated;
    log(`loaded cached feeds (${Math.round(age / 3600000)}h old)`);
  } catch {}
  if (age > DAY) refresh(log);
  fs.watchFile(CUSTOM, { interval: 2000 }, () => index(lastParsed));
  setInterval(() => { if (!status.updated || Date.now() - status.updated > DAY) refresh(log); }, 3600 * 1000).unref();
}

function lookup(ip) {
  if (!isV4(ip)) return (exact.get(ip) || []).map(id => FEEDS.find(f => f.id === id));
  if (hitCache.has(ip)) return hitCache.get(ip);
  const ids = new Set(exact.get(ip) || []);
  const n = ipToInt(ip);
  for (const c of cidrs) if (((n ^ c.net) >>> (32 - c.bits)) === 0) ids.add(c.feed);
  const hits = [...ids].map(id => FEEDS.find(f => f.id === id)).filter(Boolean);
  hitCache.set(ip, hits);
  return hits;
}

// ASN + owner via Team Cymru's DNS service
const asnNames = new Map();
async function txt(name) { return (await dns.resolveTxt(name))[0].join(''); }
async function whoisAsn(ip) {
  let q;
  if (isV4(ip)) q = ip.split('.').reverse().join('.') + '.origin.asn.cymru.com';
  else {
    const full = require('net').isIPv6(ip) ? expandV6(ip) : null;
    if (!full) return null;
    q = full.replace(/:/g, '').split('').reverse().join('.') + '.origin6.asn.cymru.com';
  }
  const f = (await txt(q)).split('|').map(s => s.trim());
  const asn = f[0].split(' ')[0];
  if (!asnNames.has(asn)) {
    const g = (await txt(`AS${asn}.asn.cymru.com`)).split('|').map(s => s.trim());
    asnNames.set(asn, g[4] || '');
  }
  return { asn: 'AS' + asn, prefix: f[1], cc: f[2], org: asnNames.get(asn) };
}
function expandV6(ip) {
  const [h, t = ''] = ip.split('::');
  const hp = h ? h.split(':') : [], tp = t ? t.split(':') : [];
  const mid = ip.includes('::') ? Array(8 - hp.length - tp.length).fill('0') : [];
  const parts = [...hp, ...mid, ...tp];
  return parts.length === 8 ? parts.map(p => p.padStart(4, '0')).join(':') : null;
}

const CLOUD = /amazon|aws|google|microsoft|azure|digitalocean|ovh|hetzner|linode|akamai|oracle|alibaba|tencent|vultr|cloudflare|contabo|leaseweb|choopa/i;
const isCloud = org => CLOUD.test(org || '');

module.exports = { DATA_DIR, init, refresh, lookup, whoisAsn, isCloud, status: () => ({ ...status, total: exact.size + cidrs.length, feedDefs: FEEDS.map(({ id, name, cat, sev }) => ({ id, name, cat, sev })) }) };
