// Domain blocklists: named sets of domains, matched on the name or any parent ("evil.com" blocks "a.b.evil.com").
// Pure: no I/O.
const net = require('net');
const NAME_RE = /^(?=.{3,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;

const norm = s => String(s || '').trim().toLowerCase().replace(/^\*\./, '').replace(/\.$/, '');
// A single label ("com") is never accepted: one bad line must not be able to blackhole a whole TLD.
const valid = s => NAME_RE.test(norm(s));

// Accepts a plain list (one domain per line) or hosts-file style ("127.0.0.1 domain"). '#' starts a comment.
function parseList(text) {
  const out = new Set();
  for (const raw of String(text).split('\n')) {
    const line = raw.replace(/#.*/, '').trim();
    if (!line) continue;
    const t = line.split(/\s+/);
    const name = norm(t.length > 1 && net.isIP(t[0]) ? t[1] : t[0]); // hosts-file lines put the address first
    if (valid(name) && !net.isIP(name)) out.add(name);
  }
  return [...out];
}

class DomainList {
  constructor() { this.lists = new Map(); }
  set(id, domains) { this.lists.set(id, new Set(domains.map(norm).filter(valid))); }
  size() { let n = 0; for (const s of this.lists.values()) n += s.size; return n; }
  // -> { list, domain } for the most specific hit, or null
  match(name) {
    let n = norm(name);
    if (!n) return null;
    for (;;) {
      for (const [id, set] of this.lists) if (set.has(n)) return { list: id, domain: n };
      const i = n.indexOf('.');
      if (i < 0) return null;
      n = n.slice(i + 1);
    }
  }
}

module.exports = { DomainList, parseList, valid, norm };
