const test = require('node:test');
const assert = require('node:assert/strict');
const A = require('../lib/appid');
const H = require('./helpers');

test('TLS ClientHello: SNI, ALPN, JA3 without GREASE', () => {
  const t = A.parseTlsClientHello(H.clientHello('api.github.com'));
  assert.equal(t.sni, 'api.github.com');
  assert.deepEqual(t.alpn, ['h2', 'http/1.1']);
  assert.equal(t.ja3, '771,4865-4866,0-16-10,29,');
  assert.match(t.ja3Hash, /^[0-9a-f]{32}$/);
});

test('TLS parser rejects garbage and truncation without throwing', () => {
  assert.equal(A.parseTlsClientHello(Buffer.from('GET / HTTP/1.1\r\n')), null);
  assert.equal(A.parseTlsClientHello(H.clientHello('example.com').subarray(0, 20)), null);
  assert.equal(A.parseTlsClientHello(Buffer.alloc(0)), null);
});

test('HTTP request: method, host (port stripped), user agent', () => {
  const h = A.parseHttpRequest(Buffer.from('GET /x HTTP/1.1\r\nHost: Example.com:8080\r\nUser-Agent: curl/8\r\n\r\n'));
  assert.deepEqual(h, { method: 'GET', path: '/x', host: 'example.com', ua: 'curl/8' });
  assert.equal(A.parseHttpRequest(Buffer.from('\x16\x03\x01')), null);
});

test('DNS query: name and type; responses ignored', () => {
  assert.deepEqual(A.parseDnsQuery(H.dnsQuery('Evil.Example.com')), { name: 'evil.example.com', qtype: 1 });
  const resp = H.dnsQuery('a.com'); resp[2] |= 0x80;
  assert.equal(A.parseDnsQuery(resp), null);
  assert.equal(A.parseDnsQuery(Buffer.alloc(5)), null);
});

test('classify: SNI beats port; port is the fallback; unknown is explicit', () => {
  assert.deepEqual(A.classify({ sni: 'r1.googlevideo.com', rport: 443 }), { app: 'youtube', via: 'sni' });
  assert.deepEqual(A.classify({ sni: 'unknown-site.example', rport: 443 }), { app: 'ssl', via: 'sni' });
  assert.deepEqual(A.classify({ rport: 22 }), { app: 'ssh', via: 'port' });
  assert.deepEqual(A.classify({ proto: 'udp', rport: 9999 }), { app: 'unknown-udp', via: 'none' });
  assert.equal(A.classify({ sni: 'notgithub.com' }).app, 'ssl'); // suffix match must respect the dot boundary
});

test('decodePacket: ethernet/IPv4/TCP and UDP', () => {
  const tcp = A.decodePacket(H.ether(H.ipv4Packet({ src: '10.0.0.2', dst: '1.2.3.4', proto: 'tcp', sport: 5000, dport: 443, payload: Buffer.from('hi') })), A.LINK.ETHERNET);
  assert.equal(tcp.src, '10.0.0.2'); assert.equal(tcp.dport, 443); assert.equal(tcp.proto, 'tcp'); assert.equal(tcp.payload.toString(), 'hi');
  const udp = A.decodePacket(H.ipv4Packet({ src: '10.0.0.2', dst: '8.8.8.8', proto: 'udp', sport: 4000, dport: 53, payload: Buffer.from('q') }), A.LINK.RAW);
  assert.equal(udp.proto, 'udp'); assert.equal(udp.payload.toString(), 'q');
});

test('decodePacket: macOS loopback (DLT_NULL) header', () => {
  const ip = H.ipv4Packet({ src: '127.0.0.1', dst: '127.0.0.1', proto: 'tcp', sport: 1, dport: 2, payload: Buffer.alloc(0) });
  const fam = Buffer.alloc(4); fam.writeUInt32LE(2);
  assert.equal(A.decodePacket(Buffer.concat([fam, ip]), A.LINK.NULL).dport, 2);
});

test('PcapStream: reassembles packets split across arbitrary chunk boundaries', () => {
  const hello = H.ether(H.ipv4Packet({ src: '10.0.0.2', dst: '93.184.216.34', proto: 'tcp', sport: 5555, dport: 443, payload: H.clientHello('example.com') }));
  const dns = H.ether(H.ipv4Packet({ src: '10.0.0.2', dst: '8.8.8.8', proto: 'udp', sport: 4444, dport: 53, payload: H.dnsQuery('example.com') }));
  const stream = H.pcap([hello, dns]);
  const seen = [];
  const ps = new A.PcapStream(p => seen.push(p));
  for (let i = 0; i < stream.length; i += 7) ps.push(stream.subarray(i, i + 7));
  assert.equal(seen.length, 2);
  assert.equal(A.inspectPayload(seen[0]).sni, 'example.com');
  assert.equal(A.inspectPayload(seen[1]).dnsName, 'example.com');
});

test('PcapStream rejects non-pcap input', () => {
  assert.throws(() => new A.PcapStream(() => {}).push(Buffer.alloc(40, 7)), /not a pcap/);
});
