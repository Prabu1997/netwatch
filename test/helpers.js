// Builders for synthetic packets so tests need no network, root, or tcpdump.
const u16 = n => { const b = Buffer.alloc(2); b.writeUInt16BE(n); return b; };

function clientHello(sni, { alpn = ['h2', 'http/1.1'] } = {}) {
  const name = Buffer.from(sni);
  const sniExt = Buffer.concat([u16(0), u16(name.length + 5), u16(name.length + 3), Buffer.from([0]), u16(name.length), name]);
  const al = Buffer.concat(alpn.map(a => Buffer.concat([Buffer.from([a.length]), Buffer.from(a)])));
  const alpnExt = Buffer.concat([u16(16), u16(al.length + 2), u16(al.length), al]);
  const groups = Buffer.concat([u16(10), u16(6), u16(4), u16(0x0a0a), u16(29)]); // GREASE + x25519
  const exts = Buffer.concat([sniExt, alpnExt, groups]);
  const ciphers = Buffer.concat([u16(0x1301), u16(0x1302), u16(0x0a0a)]);
  const body = Buffer.concat([u16(0x0303), Buffer.alloc(32, 1), Buffer.from([0]), u16(ciphers.length), ciphers, Buffer.from([1, 0]), u16(exts.length), exts]);
  const hs = Buffer.concat([Buffer.from([1, 0]), u16(body.length), body]);
  return Buffer.concat([Buffer.from([0x16, 3, 1]), u16(hs.length), hs]);
}

function dnsQuery(name) {
  const q = Buffer.concat([...name.split('.').map(l => Buffer.concat([Buffer.from([l.length]), Buffer.from(l)])), Buffer.from([0]), u16(1), u16(1)]);
  return Buffer.concat([u16(0x1234), u16(0x0100), u16(1), u16(0), u16(0), u16(0), q]);
}

function ipv4Packet({ src, dst, proto, sport, dport, payload, flags = 0x18 }) {
  const ip = s => Buffer.from(s.split('.').map(Number));
  const l4 = proto === 'tcp'
    ? Buffer.concat([u16(sport), u16(dport), Buffer.alloc(8), Buffer.from([0x50, flags]), Buffer.alloc(6)])
    : Buffer.concat([u16(sport), u16(dport), u16(8 + payload.length), u16(0)]);
  const total = 20 + l4.length + payload.length;
  const h = Buffer.concat([Buffer.from([0x45, 0]), u16(total), Buffer.alloc(4), Buffer.from([64, proto === 'tcp' ? 6 : 17]), u16(0), ip(src), ip(dst)]);
  return Buffer.concat([h, l4, payload]);
}

const ether = ip => Buffer.concat([Buffer.alloc(12), u16(0x0800), ip]);

function pcap(packets, linktype = 1) {
  const g = Buffer.alloc(24); g.writeUInt32LE(0xa1b2c3d4 >>> 0, 0); g.writeUInt16LE(2, 4); g.writeUInt16LE(4, 6); g.writeUInt32LE(65535, 16); g.writeUInt32LE(linktype, 20);
  return Buffer.concat([g, ...packets.map(p => { const r = Buffer.alloc(16); r.writeUInt32LE(1, 0); r.writeUInt32LE(p.length, 8); r.writeUInt32LE(p.length, 12); return Buffer.concat([r, p]); })]);
}

module.exports = { clientHello, dnsQuery, ipv4Packet, ether, pcap };
