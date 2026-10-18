// Loads domain blocklists into a DomainList: a public malware-host feed (cached, refreshed daily) and the user's
// own data/domains.txt. Every file goes through the trusted store.
const fs = require('fs');
const path = require('path');
const store = require('./store');
const { parseList } = require('./domains');

const DAY = 24 * 3600 * 1000;
const FEEDS = [{ id: 'urlhaus', name: 'abuse.ch URLhaus (malware hosts)', url: 'https://urlhaus.abuse.ch/downloads/hostfile/' }];

function init(domains, dir, log = console.log) {
  const status = { feeds: {}, custom: 0 };
  const customFile = path.join(dir, 'domains.txt');

  const loadCustom = () => {
    const txt = store.read(customFile);
    if (txt === null) return; // missing or untrusted: keep whatever was last loaded
    const list = parseList(txt);
    domains.set('custom', list); status.custom = list.length;
  };
  loadCustom();
  fs.watchFile(customFile, { interval: 2000 }, loadCustom);

  for (const f of FEEDS) {
    const cache = path.join(dir, `domains-${f.id}.txt`);
    let age = Infinity;
    const txt = store.read(cache);
    if (txt !== null) {
      const l = parseList(txt); domains.set(f.id, l); status.feeds[f.id] = { ok: true, count: l.length };
      try { age = Date.now() - fs.statSync(cache).mtimeMs; } catch {}
    }
    const refresh = async () => {
      try {
        const r = await fetch(f.url, { signal: AbortSignal.timeout(30000), headers: { 'User-Agent': 'netwatch-local/1.0' } });
        if (!r.ok) throw new Error('HTTP ' + r.status);
        const body = await r.text();
        const l = parseList(body);
        if (!l.length) throw new Error('empty feed');
        domains.set(f.id, l); status.feeds[f.id] = { ok: true, count: l.length, at: Date.now() };
        store.write(cache, body);
        log(`domain feed ${f.id}: ${l.length} domains`);
      } catch (e) {
        status.feeds[f.id] = { ...(status.feeds[f.id] || { count: 0 }), ok: false, error: String(e.message || e) };
        log(`domain feed ${f.id} failed: ${e.message}`);
      }
    };
    if (age > DAY) refresh();
    setInterval(() => { refresh(); }, DAY).unref();
  }
  return status;
}

module.exports = { init, FEEDS };
