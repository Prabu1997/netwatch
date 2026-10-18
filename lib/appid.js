// App-ID: pure functions that identify the application from packet bytes. No I/O, so they test on any OS.
const crypto = require('crypto');

const isGrease = v => (v & 0x0f0f) === 0x0a0a && (v >> 8) === (v & 0xff);

// ---- TLS ClientHello: SNI, ALPN, JA3 ----
function parseTlsClientHello(b) {
  try {
    if (b.length < 6 || b[0] !== 0x16 || b[1] !== 3 || b[5] !== 1) return null; // handshake record, ClientHello
    let o = 9; // record(5) + handshake type(1) + length(3)
    const version = b.readUInt16BE(o); o += 2 + 32; // version + random
    o += 1 + b[o]; // session id
    const cl = b.readUInt16BE(o); o += 2;
    const ciphers = [];
    for (let i = 0; i < cl; i += 2) ciphers.push(b.readUInt16BE(o + i));
    o += cl;
    o += 1 + b[o]; // compression
    const extEnd = o + 2 + b.readUInt16BE(o); o += 2;
    const exts = [], curves = [], points = [], alpn = [];
    let sni = null;
    while (o + 4 <= extEnd && o + 4 <= b.length) {
      const type = b.readUInt16BE(o), len = b.readUInt16BE(o + 2), d = o + 4;
      exts.push(type);
      if (type === 0 && len >= 5) { // server_name
        const nl = b.readUInt16BE(d + 3);
        sni = b.toString('ascii', d + 5, d + 5 + nl).toLowerCase();
      } else if (type === 10) {
        for (let i = 2; i < len; i += 2) curves.push(b.readUInt16BE(d + i));
      } else if (type === 11) {
        for (let i = 1; i < len; i++) points.push(b[d + i]);
      } else if (type === 16) {
        for (let i = d + 2; i < d + len;) { const l = b[i]; alpn.push(b.toString('ascii', i + 1, i + 1 + l)); i += 1 + l; }
      }
      o = d + len;
    }
    const f = a => a.filter(v => !isGrease(v));
    const ja3 = [version, f(ciphers).join('-'), f(exts).join('-'), f(curves).join('-'), points.join('-')].join(',');
    return { sni, alpn, ja3, ja3Hash: crypto.createHash('md5').update(ja3).digest('hex') };
  } catch { return null; }
}

// ---- HTTP/1.x request ----
const HTTP_METHODS = /^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT) (\S+) HTTP\/1\.[01]\r\n/;
function parseHttpRequest(b) {
  const s = b.toString('latin1', 0, Math.min(b.length, 2048));
  const m = s.match(HTTP_METHODS);
  if (!m) return null;
  const host = (s.match(/\r\nHost:\s*([^\r\n]+)/i) || [])[1];
  const ua = (s.match(/\r\nUser-Agent:\s*([^\r\n]+)/i) || [])[1];
  return { method: m[1], path: m[2], host: host ? host.trim().toLowerCase().replace(/:\d+$/, '') : null, ua: ua || null };
}

// ---- DNS query (UDP payload) ----
function parseDnsQuery(b) {
  try {
    if (b.length < 17) return null;
    const flags = b.readUInt16BE(2);
    if (flags & 0x8000) return null; // response
    if (b.readUInt16BE(4) < 1) return null;
    const labels = [];
    let o = 12;
    while (b[o]) {
      const l = b[o];
      if (l > 63 || o + 1 + l > b.length) return null;
      labels.push(b.toString('ascii', o + 1, o + 1 + l));
      o += 1 + l;
    }
    return { name: labels.join('.').toLowerCase(), qtype: b.readUInt16BE(o + 1) };
  } catch { return null; }
}

// ---- classification ----
// Suffix table: first match wins. Deliberately small and editable; extend it via data/apps.json later.
const APPS = [
  ['youtube', /(^|\.)(youtube\.com|googlevideo\.com|ytimg\.com)$/], ['google', /(^|\.)(google\.com|googleapis\.com|gstatic\.com|gvt1\.com)$/],
  ['github', /(^|\.)(github\.com|githubusercontent\.com|githubassets\.com)$/], ['anthropic', /(^|\.)(anthropic\.com|claude\.ai)$/],
  ['microsoft', /(^|\.)(microsoft\.com|office\.com|live\.com|windows\.net|msftconnecttest\.com)$/], ['apple', /(^|\.)(apple\.com|icloud\.com|mzstatic\.com)$/],
  ['slack', /(^|\.)(slack\.com|slack-edge\.com)$/], ['zoom', /(^|\.)(zoom\.us|zoom\.com)$/],
  ['netflix', /(^|\.)(netflix\.com|nflxvideo\.net)$/], ['facebook', /(^|\.)(facebook\.com|fbcdn\.net|instagram\.com|whatsapp\.net)$/],
  ['dropbox', /(^|\.)(dropbox\.com|dropboxapi\.com)$/], ['cloudflare', /(^|\.)(cloudflare\.com|cloudflare-dns\.com)$/],
  ['npm', /(^|\.)(npmjs\.org|npmjs\.com)$/], ['docker', /(^|\.)(docker\.com|docker\.io)$/],
];
const PORT_APPS = { 22: 'ssh', 25: 'smtp', 53: 'dns', 80: 'web-browsing', 123: 'ntp', 143: 'imap', 443: 'ssl', 465: 'smtps', 587: 'smtp-submission',
  853: 'dns-over-tls', 993: 'imaps', 995: 'pop3s', 3306: 'mysql', 5432: 'postgres', 6379: 'redis', 3389: 'rdp', 5353: 'mdns', 1900: 'ssdp' };

function classify({ sni, host, dnsName, proto, rport, alpn }) {
  const name = sni || host || dnsName;
  if (name) for (const [app, re] of APPS) if (re.test(name)) return { app, via: sni ? 'sni' : host ? 'http-host' : 'dns' };
  if (dnsName) return { app: 'dns', via: 'payload' };
  if (alpn && alpn.includes('h3')) return { app: 'quic', via: 'alpn' };
  if (host) return { app: 'web-browsing', via: 'http-host' };
  if (sni) return { app: 'ssl', via: 'sni' };
  if (PORT_APPS[rport]) return { app: PORT_APPS[rport], via: 'port' };
  return { app: 'unknown-' + (proto || 'tcp'), via: 'none' };
}

// ---- link + IP + transport decode ----
const LINK = { NULL: 0, ETHERNET: 1, RAW: 12, RAW2: 101, SLL: 113, SLL2: 276 };

function ipv4Str(b, o) { return `${b[o]}.${b[o + 1]}.${b[o + 2]}.${b[o + 3]}`; }
function ipv6Str(b, o) {
  const g = []; for (let i = 0; i < 8; i++) g.push(b.readUInt16BE(o + i * 2).toString(16));
  return g.join(':').replace(/(^|:)0(:0)+(:|$)/, '::').replace(/^0::/, '::');
}

function decodePacket(b, linktype) {
  let o = 0, ethertype;
  switch (linktype) {
    case LINK.ETHERNET: ethertype = b.readUInt16BE(12); o = 14;
      while (ethertype === 0x8100 || ethertype === 0x88a8) { ethertype = b.readUInt16BE(o + 2); o += 4; }
      break;
    case LINK.NULL: { const fam = b.readUInt32LE(0); ethertype = fam === 2 ? 0x0800 : 0x86dd; o = 4; break; } // macOS loopback: AF_INET=2, else v6
    case LINK.SLL: ethertype = b.readUInt16BE(14); o = 16; break;
    case LINK.SLL2: ethertype = b.readUInt16BE(0); o = 20; break;
    case LINK.RAW: case LINK.RAW2: ethertype = (b[0] >> 4) === 4 ? 0x0800 : 0x86dd; break;
    default: return null;
  }
  let src, dst, proto, hdr;
  if (ethertype === 0x0800) {
    hdr = (b[o] & 0x0f) * 4; proto = b[o + 9]; src = ipv4Str(b, o + 12); dst = ipv4Str(b, o + 16);
    const total = b.readUInt16BE(o + 2);
    var end = Math.min(b.length, total ? o + total : b.length);
  } else if (ethertype === 0x86dd) {
    hdr = 40; proto = b[o + 6]; src = ipv6Str(b, o + 8); dst = ipv6Str(b, o + 24);
    end = Math.min(b.length, o + 40 + b.readUInt16BE(o + 4));
  } else return null;
  o += hdr;
  if (proto === 6) {
    const doff = (b[o + 12] >> 4) * 4;
    return { src, dst, proto: 'tcp', sport: b.readUInt16BE(o), dport: b.readUInt16BE(o + 2), flags: b[o + 13], payload: b.subarray(o + doff, end) };
  }
  if (proto === 17) return { src, dst, proto: 'udp', sport: b.readUInt16BE(o), dport: b.readUInt16BE(o + 2), flags: 0, payload: b.subarray(o + 8, end) };
  return { src, dst, proto: String(proto), sport: 0, dport: 0, flags: 0, payload: Buffer.alloc(0) };
}

// Inspect one decoded packet's payload and return whatever identity it reveals.
function inspectPayload(p) {
  if (!p.payload.length) return null;
  if (p.proto === 'tcp') {
    const t = parseTlsClientHello(p.payload);
    if (t) return { sni: t.sni, alpn: t.alpn, ja3: t.ja3Hash };
    const h = parseHttpRequest(p.payload);
    if (h) return { host: h.host, method: h.method, ua: h.ua };
  } else if (p.proto === 'udp' && (p.dport === 53 || p.dport === 5353)) {
    const d = parseDnsQuery(p.payload);
    if (d) return { dnsName: d.name, qtype: d.qtype };
  }
  return null;
}

// ---- streaming pcap reader (tcpdump -w -) ----
class PcapStream {
  constructor(onPacket) { this.buf = Buffer.alloc(0); this.onPacket = onPacket; this.le = true; this.linktype = null; }
  push(chunk) {
    this.buf = this.buf.length ? Buffer.concat([this.buf, chunk]) : chunk;
    if (this.linktype === null) {
      if (this.buf.length < 24) return;
      const magic = this.buf.readUInt32BE(0);
      if (magic === 0xa1b2c3d4 || magic === 0xa1b23c4d) this.le = false;
      else if (magic === 0xd4c3b2a1 || magic === 0x4d3cb2a1) this.le = true;
      else throw new Error('not a pcap stream');
      this.linktype = this.le ? this.buf.readUInt32LE(20) : this.buf.readUInt32BE(20);
      this.buf = this.buf.subarray(24);
    }
    while (this.buf.length >= 16) {
      const incl = this.le ? this.buf.readUInt32LE(8) : this.buf.readUInt32BE(8);
      if (this.buf.length < 16 + incl) break;
      const sec = this.le ? this.buf.readUInt32LE(0) : this.buf.readUInt32BE(0);
      const data = this.buf.subarray(16, 16 + incl);
      this.buf = this.buf.subarray(16 + incl);
      let pkt = null;
      try { pkt = decodePacket(data, this.linktype); } catch {}
      if (pkt) this.onPacket(pkt, sec * 1000);
    }
  }
}

module.exports = { parseTlsClientHello, parseHttpRequest, parseDnsQuery, classify, decodePacket, inspectPayload, PcapStream, LINK };
