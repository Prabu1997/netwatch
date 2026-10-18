// A small DNS filtering proxy. Clients point at it; blocked names get NXDOMAIN, everything else is forwarded
// untouched to a real resolver. Blocking by name avoids the collateral damage of blocking a shared CDN address.
// UDP only (TCP fallback and DoH/DoT are not intercepted: see README).
const dgram = require('dgram');
const net = require('net');

// Parse the first question of a DNS query. Returns null for anything that isn't a plain, well-formed query.
function parseQuestion(b) {
  if (b.length < 17) return null;
  const flags = b.readUInt16BE(2);
  if (flags & 0x8000) return null;                 // a response, not a query
  if (((flags >> 11) & 0xf) !== 0) return null;    // only standard queries
  if (b.readUInt16BE(4) < 1) return null;
  const labels = [];
  let o = 12, total = 0;
  while (true) {
    if (o >= b.length) return null;
    const l = b[o];
    if (l === 0) { o++; break; }
    if (l > 63) return null;                       // 0xC0 compression pointers never appear in a question
    if (o + 1 + l > b.length) return null;
    total += l + 1; if (total > 253) return null;
    labels.push(b.toString('latin1', o + 1, o + 1 + l));
    o += 1 + l;
  }
  if (o + 4 > b.length) return null;
  return { name: labels.join('.').toLowerCase(), qtype: b.readUInt16BE(o), qclass: b.readUInt16BE(o + 2), end: o + 4, rd: !!(flags & 0x0100) };
}

// Header + the original question, with the given response code. RA set; RD echoed.
function reply(query, q, rcode) {
  const h = Buffer.alloc(12);
  query.copy(h, 0, 0, 2);                                            // transaction id
  h.writeUInt16BE(0x8000 | (q.rd ? 0x0100 : 0) | 0x0080 | rcode, 2); // QR, RD, RA, RCODE
  h.writeUInt16BE(1, 4);
  return Buffer.concat([h, query.subarray(12, q.end)]);
}
const NXDOMAIN = 3, SERVFAIL = 2;

class DnsFilter {
  // decide(name, qtype) -> { action: 'allow'|'deny'|'alert', why? };  upstreams() -> [ip]
  constructor({ decide, upstreams, timeoutMs = 3000, onDecision = () => {}, log = console.log }) {
    Object.assign(this, { decide, upstreams, timeoutMs, onDecision, log });
    this.stats = { queries: 0, blocked: 0, forwarded: 0, failed: 0 };
    this.sock = null; this.port = null; this.error = null;
  }

  start(port = 53, host = '127.0.0.1') {
    return new Promise(resolve => {
      const sock = dgram.createSocket(net.isIPv6(host) ? 'udp6' : 'udp4');
      sock.on('error', e => { this.error = e.code === 'EACCES' ? `cannot bind port ${port}: needs root` : e.code === 'EADDRINUSE' ? `port ${port} already in use` : e.message; this.log('dns filter: ' + this.error); resolve(false); });
      sock.on('message', (msg, rinfo) => { try { this.handle(msg, rinfo); } catch (e) { this.stats.failed++; } });
      sock.bind(port, host, () => { this.sock = sock; this.port = sock.address().port; this.error = null; resolve(true); });
    });
  }
  stop() { try { this.sock && this.sock.close(); } catch {} this.sock = null; }

  handle(msg, rinfo) {
    const q = parseQuestion(msg);
    if (!q) return;                                   // junk: no answer, nothing to amplify
    this.stats.queries++;
    const d = this.decide(q.name, q.qtype) || { action: 'allow' };
    this.onDecision({ t: Date.now(), name: q.name, qtype: q.qtype, action: d.action, why: d.why || null, from: rinfo.address });
    if (d.action === 'deny') {
      this.stats.blocked++;
      this.sock.send(reply(msg, q, NXDOMAIN), rinfo.port, rinfo.address);
      return;
    }
    this.forward(msg, q, rinfo);
  }

  // Try each upstream in turn; the first answer wins. Nothing is rewritten.
  forward(msg, q, rinfo) {
    const ups = this.upstreams();
    const fail = () => { this.stats.failed++; this.sock && this.sock.send(reply(msg, q, SERVFAIL), rinfo.port, rinfo.address); };
    const tryNext = i => {
      if (i >= ups.length) return fail();
      const up = typeof ups[i] === 'string' ? { host: ups[i], port: 53 } : ups[i];
      const s = dgram.createSocket(net.isIPv6(up.host) ? 'udp6' : 'udp4');
      const timer = setTimeout(() => { s.close(); tryNext(i + 1); }, this.timeoutMs);
      s.on('error', () => { clearTimeout(timer); try { s.close(); } catch {} tryNext(i + 1); });
      s.on('message', ans => {
        clearTimeout(timer); s.close();
        if (ans.length >= 2 && ans[0] === msg[0] && ans[1] === msg[1]) { // must answer *this* query
          this.stats.forwarded++;
          this.sock && this.sock.send(ans, rinfo.port, rinfo.address);
        } else tryNext(i + 1);
      });
      s.send(msg, up.port, up.host, err => { if (err) { clearTimeout(timer); try { s.close(); } catch {} tryNext(i + 1); } });
    };
    tryNext(0);
  }
}

module.exports = { DnsFilter, parseQuestion, reply, NXDOMAIN, SERVFAIL };
