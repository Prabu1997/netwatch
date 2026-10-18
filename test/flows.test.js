const test = require('node:test');
const assert = require('node:assert/strict');
const { FlowTable, key } = require('../lib/flows');
const A = require('../lib/appid');
const H = require('./helpers');

const pkt = o => A.decodePacket(H.ipv4Packet(o), A.LINK.RAW);

test('flow key is direction-independent', () => {
  assert.equal(key('tcp', '10.0.0.2', 5000, '1.1.1.1', 443), key('tcp', '1.1.1.1', 443, '10.0.0.2', 5000));
});

test('ClientHello labels the flow and the destination name; later packets keep the label', () => {
  const t = new FlowTable();
  t.observe(pkt({ src: '10.0.0.2', dst: '140.82.112.4', proto: 'tcp', sport: 5000, dport: 443, payload: H.clientHello('api.github.com') }));
  t.observe(pkt({ src: '140.82.112.4', dst: '10.0.0.2', proto: 'tcp', sport: 443, dport: 5000, payload: Buffer.from('serverdata') }));
  const f = t.get('tcp', '10.0.0.2', 5000, '140.82.112.4', 443);
  assert.equal(f.app, 'github'); assert.equal(f.via, 'sni'); assert.equal(f.sni, 'api.github.com');
  assert.equal(t.nameFor('140.82.112.4'), 'api.github.com');
});

test('payload with no identity does not create flows; DNS is labelled dns', () => {
  const t = new FlowTable();
  t.observe(pkt({ src: '10.0.0.2', dst: '9.9.9.9', proto: 'tcp', sport: 1, dport: 2, payload: Buffer.from('opaque') }));
  assert.equal(t.flows.size, 0);
  t.observe(pkt({ src: '10.0.0.2', dst: '8.8.8.8', proto: 'udp', sport: 4000, dport: 53, payload: H.dnsQuery('evil.example') }));
  assert.equal(t.get('udp', '10.0.0.2', 4000, '8.8.8.8', 53).app, 'dns');
});

test('expire drops idle flows only', () => {
  const t = new FlowTable();
  t.observe(pkt({ src: '10.0.0.2', dst: '8.8.8.8', proto: 'udp', sport: 4000, dport: 53, payload: H.dnsQuery('a.com') }), 1000);
  t.expire(1000 + 60000); assert.equal(t.flows.size, 1);
  t.expire(1000 + 11 * 60000); assert.equal(t.flows.size, 0);
});
