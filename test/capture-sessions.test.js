const test = require('node:test');
const assert = require('node:assert/strict');
const { normIp, formatV6 } = require('../lib/ip');
const { FlowTable, connKey } = require('../lib/flows');
const { packetOnly } = require('../lib/sessionmerge');
const A = require('../lib/appid');
const H = require('./helpers');

const ME = '10.0.0.2', ME6 = '2001:db8::2';
const table = () => new FlowTable({ isLocal: ip => [normIp(ME), normIp(ME6)].includes(normIp(ip)) });
const dec = (o, v6) => A.decodePacket(v6 ? H.ipv6Packet(o) : H.ipv4Packet(o), A.LINK.RAW);
const SYN = 0x02, SYNACK = 0x12, ACK = 0x10;

test('normIp: v6 forms from ss/lsof and from the packet decoder compare equal', () => {
  const forms = ['2001:db8::2', '2001:0db8:0000:0000:0000:0000:0000:0002', '2001:DB8:0:0:0:0:0:2', '[2001:db8::2]', 'fe80::1%en0'];
  assert.equal(new Set(forms.slice(0, 4).map(normIp)).size, 1);
  assert.equal(normIp('fe80::1%en0'), normIp('fe80::1'));
  assert.equal(normIp('::ffff:1.2.3.4'), '1.2.3.4');
  assert.equal(normIp('::'), '0000:0000:0000:0000:0000:0000:0000:0000');
  assert.equal(normIp('1.2.3.4'), '1.2.3.4');
});

test('formatV6: RFC 5952 text, longest zero run only, single zero group not compressed', () => {
  assert.equal(formatV6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 2]), '2001:db8::2');
  assert.equal(formatV6([0, 0, 0, 0, 0, 0, 0, 1]), '::1');
  assert.equal(formatV6([0, 0, 0, 0, 0, 0, 0, 0]), '::');
  assert.equal(formatV6([0x2001, 0xdb8, 0, 1, 0, 0, 0, 1]), '2001:db8:0:1::1');
  assert.equal(formatV6([0x2001, 0xdb8, 0, 1, 1, 1, 1, 1]), '2001:db8:0:1:1:1:1:1');
  assert.equal(formatV6([1, 0, 0, 1, 0, 0, 1, 1]), '1::1:0:0:1:1'); // ties: first run wins
});

test('decoder prints v6 the same way the OS does', () => {
  const p = dec({ src: [0x2001, 0xdb8, 0, 0, 0, 0, 0, 2], dst: [0x2606, 0x4700, 0, 0, 0, 0, 0, 0x6810], proto: 'tcp', sport: 5, dport: 443, payload: Buffer.alloc(0), flags: SYN }, true);
  assert.equal(p.src, '2001:db8::2'); assert.equal(p.dst, '2606:4700::6810');
});

test('a connection that opens and closes between polls is still recorded (SYN seen)', () => {
  const t = table();
  t.observe(dec({ src: ME, dst: '203.0.113.9', proto: 'tcp', sport: 50000, dport: 4444, payload: Buffer.alloc(0), flags: SYN }), 1000);
  t.observe(dec({ src: '203.0.113.9', dst: ME, proto: 'tcp', sport: 4444, dport: 50000, payload: Buffer.from('x'.repeat(100)), flags: SYNACK }), 1100);
  assert.equal(t.conns.size, 1);
  const c = [...t.conns.values()][0];
  assert.deepEqual([c.rip, c.rport, c.lport, c.pktsOut, c.pktsIn, c.bytesIn], ['203.0.113.9', 4444, 50000, 1, 1, 100]);
});

test('not tracked: inbound-initiated, mid-stream TCP, loopback, multicast, DNS/NTP one-shots', () => {
  const t = table();
  t.observe(dec({ src: '198.51.100.7', dst: ME, proto: 'tcp', sport: 4000, dport: 22, payload: Buffer.alloc(0), flags: SYN }));      // inbound scan
  t.observe(dec({ src: ME, dst: '203.0.113.9', proto: 'tcp', sport: 50001, dport: 443, payload: Buffer.from('data'), flags: ACK }));   // mid-stream
  t.observe(dec({ src: ME, dst: ME, proto: 'tcp', sport: 1, dport: 2, payload: Buffer.alloc(0), flags: SYN }));                         // loopback
  t.observe(dec({ src: ME, dst: '224.0.0.251', proto: 'udp', sport: 5353, dport: 5353, payload: Buffer.from('x') }));                   // mDNS
  t.observe(dec({ src: ME, dst: '8.8.8.8', proto: 'udp', sport: 40000, dport: 53, payload: Buffer.from('x') }));                        // DNS
  t.observe(dec({ src: ME, dst: '17.1.1.1', proto: 'udp', sport: 40001, dport: 123, payload: Buffer.from('x') }));                      // NTP
  assert.equal(t.conns.size, 0);
});

test('UDP/QUIC: first outbound packet creates the flow; replies are counted, not new flows', () => {
  const t = table();
  t.observe(dec({ src: ME, dst: '142.250.1.1', proto: 'udp', sport: 61000, dport: 443, payload: Buffer.from('q'.repeat(50)) }), 1);
  t.observe(dec({ src: '142.250.1.1', dst: ME, proto: 'udp', sport: 443, dport: 61000, payload: Buffer.from('r'.repeat(70)) }), 2);
  assert.equal(t.conns.size, 1);
  const c = [...t.conns.values()][0];
  assert.deepEqual([c.proto, c.rport, c.bytesOut, c.bytesIn], ['udp', 443, 50, 70]);
  assert.deepEqual(A.classify({ proto: 'udp', rport: 443 }), { app: 'quic', via: 'port' });
});

test('IPv6 outbound flow is tracked', () => {
  const t = table();
  t.observe(dec({ src: [0x2001, 0xdb8, 0, 0, 0, 0, 0, 2], dst: [0x2606, 0x4700, 0, 0, 0, 0, 0, 0x6810], proto: 'tcp', sport: 5, dport: 443, payload: Buffer.alloc(0), flags: SYN }, true));
  assert.equal(t.conns.size, 1);
  assert.equal([...t.conns.values()][0].rip, '2606:4700::6810');
});

test('flood protection: conns are capped and expire', () => {
  const t = table();
  for (let i = 0; i < 20500; i++)
    t.observe(dec({ src: ME, dst: '203.0.113.' + (i % 250 + 1), proto: 'tcp', sport: 1024 + (i % 60000), dport: 1000 + Math.floor(i / 250), payload: Buffer.alloc(0), flags: SYN }), 1);
  assert.ok(t.conns.size <= 20000, 'size ' + t.conns.size);
  t.expire(1 + 11 * 60000);
  assert.equal(t.conns.size, 0);
});

// ---- merging with the socket list ----
const row = (o = {}) => ({ proto: 'tcp', state: 'ESTAB', lip: ME, lport: 50000, rip: '203.0.113.9', rport: 443, proc: 'curl', pid: 7, holders: ['curl'], ...o });

test('merge: a flow already in the socket list is not duplicated', () => {
  const t = table();
  t.observe(dec({ src: ME, dst: '203.0.113.9', proto: 'tcp', sport: 50000, dport: 443, payload: Buffer.alloc(0), flags: SYN }), 1000);
  assert.deepEqual(packetOnly(t.conns, [row()], 1500), []);
});

test('merge: v6 text differences between lsof and the decoder still dedupe', () => {
  const t = table();
  t.observe(dec({ src: [0x2001, 0xdb8, 0, 0, 0, 0, 0, 2], dst: [0x2606, 0x4700, 0, 0, 0, 0, 0, 0x6810], proto: 'tcp', sport: 5, dport: 443, payload: Buffer.alloc(0), flags: SYN }, true), 1000);
  const r = row({ lip: '2001:0db8:0:0:0:0:0:2', lport: 5, rip: '2606:4700:0:0:0:0:0:6810' });
  assert.deepEqual(packetOnly(t.conns, [r], 1500), []);
});

test('merge: a short-lived connection the socket list never saw appears, live, with no owner', () => {
  const t = table();
  t.observe(dec({ src: ME, dst: '203.0.113.9', proto: 'tcp', sport: 50002, dport: 4444, payload: Buffer.alloc(0), flags: SYN }), 1000);
  const m = packetOnly(t.conns, [], 2000);
  assert.equal(m.length, 1);
  assert.equal(m[0].live, true); assert.equal(m[0].owner, null); assert.equal(m[0].rec.rport, 4444);
  assert.equal(packetOnly(t.conns, [], 1000 + 6000)[0].live, false); // aged out of the live window
});

test('merge: an unconnected UDP socket (QUIC) is attributed to its process by local port', () => {
  const t = table();
  t.observe(dec({ src: ME, dst: '142.250.1.1', proto: 'udp', sport: 61000, dport: 443, payload: Buffer.from('q') }), 1000);
  const udpRow = { proto: 'udp', state: 'UNCONN', lip: '*', lport: 61000, rip: '*', rport: 0, proc: 'Google Chrome', pid: 99, holders: ['Google Chrome'] };
  const m = packetOnly(t.conns, [udpRow], 1500);
  assert.equal(m.length, 1);
  assert.equal(m[0].owner.proc, 'Google Chrome'); assert.equal(m[0].owner.pid, 99);
});

test('merge: a socket-list session that has since closed suppresses its packet twin', () => {
  const t = table();
  t.observe(dec({ src: ME, dst: '203.0.113.9', proto: 'tcp', sport: 50000, dport: 443, payload: Buffer.alloc(0), flags: SYN }), 1000);
  const known = new Set([connKey('tcp', ME, 50000, '203.0.113.9', 443)]);
  assert.deepEqual(packetOnly(t.conns, [], 1500, { known }), []);
});
