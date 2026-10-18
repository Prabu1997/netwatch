const test = require('node:test');
const assert = require('node:assert/strict');
const N = require('../lib/anomaly');
const { Baseline } = require('../lib/baseline');
const { FlowTable } = require('../lib/flows');
const A = require('../lib/appid');
const H = require('./helpers');

const pkt = o => A.decodePacket(H.ipv4Packet(o), A.LINK.RAW);
const msgs = (flow, s) => N.protocolMismatch(flow, s).map(f => f[1]);

test('mismatch: SSH on web/DNS ports is flagged, SSH on 22 or 2222 is not', () => {
  assert.equal(N.protocolMismatch({ l7: 'ssh' }, { rport: 443, proto: 'tcp' }).length, 1);
  assert.equal(N.protocolMismatch({ l7: 'ssh' }, { rport: 53, proto: 'tcp' }).length, 1);
  assert.equal(N.protocolMismatch({ l7: 'ssh' }, { rport: 22, proto: 'tcp' }).length, 0);
  assert.equal(N.protocolMismatch({ l7: 'ssh' }, { rport: 2222, proto: 'tcp' }).length, 0);
});

test('mismatch: plain HTTP on 443 and TLS on 80/22 are flagged, normal pairings are not', () => {
  assert.equal(N.protocolMismatch({ l7: 'http' }, { rport: 443, proto: 'tcp' }).length, 1);
  assert.equal(N.protocolMismatch({ l7: 'http' }, { rport: 80, proto: 'tcp' }).length, 0);
  assert.equal(N.protocolMismatch({ l7: 'tls' }, { rport: 80, proto: 'tcp' }).length, 1);
  assert.equal(N.protocolMismatch({ l7: 'tls' }, { rport: 22, proto: 'tcp' }).length, 1);
  assert.equal(N.protocolMismatch({ l7: 'tls' }, { rport: 443, proto: 'tcp' }).length, 0);
});

test('mismatch: STARTTLS ports never flagged; UDP and unknown flows are ignored', () => {
  for (const p of [25, 587, 143, 110, 21, 5222]) assert.equal(N.protocolMismatch({ l7: 'tls' }, { rport: p, proto: 'tcp' }).length, 0, 'port ' + p);
  assert.deepEqual(N.protocolMismatch(null, { rport: 443, proto: 'tcp' }), []);
  assert.deepEqual(N.protocolMismatch({}, { rport: 443, proto: 'tcp' }), []);
  assert.deepEqual(N.protocolMismatch({ l7: 'ssh' }, { rport: 443, proto: 'udp' }), []);
});

test('end to end: an SSH banner on port 443 is recognised from raw packets', () => {
  const t = new FlowTable();
  t.observe(pkt({ src: '10.0.0.2', dst: '54.1.2.3', proto: 'tcp', sport: 51000, dport: 443, payload: Buffer.from('SSH-2.0-OpenSSH_9.6\r\n') }));
  const f = t.get('tcp', '10.0.0.2', 51000, '54.1.2.3', 443);
  assert.equal(f.l7, 'ssh'); assert.equal(f.app, 'ssh'); assert.equal(f.via, 'payload');
  assert.equal(msgs(f, { rport: 443, proto: 'tcp' }).length, 1);
});

test('end to end: real ClientHello on 443 raises nothing; on port 80 it does', () => {
  const t = new FlowTable();
  t.observe(pkt({ src: '10.0.0.2', dst: '1.2.3.4', proto: 'tcp', sport: 1111, dport: 443, payload: H.clientHello('example.com') }));
  t.observe(pkt({ src: '10.0.0.2', dst: '1.2.3.5', proto: 'tcp', sport: 2222, dport: 80, payload: H.clientHello('example.com') }));
  assert.equal(msgs(t.get('tcp', '10.0.0.2', 1111, '1.2.3.4', 443), { rport: 443, proto: 'tcp' }).length, 0);
  assert.equal(msgs(t.get('tcp', '10.0.0.2', 2222, '1.2.3.5', 80), { rport: 80, proto: 'tcp' }).length, 1);
});

test('SSH detection does not misfire on short or lookalike payloads', () => {
  assert.equal(A.inspectPayload(pkt({ src: '1.1.1.1', dst: '2.2.2.2', proto: 'tcp', sport: 1, dport: 2, payload: Buffer.from('SSH-') })), null);
  assert.equal(A.inspectPayload(pkt({ src: '1.1.1.1', dst: '2.2.2.2', proto: 'tcp', sport: 1, dport: 2, payload: Buffer.from('ssh-2.0-x\r\n') })), null);
});

test('isRisky: interpreters and download tools yes, browsers and apps no, versions and paths normalised', () => {
  for (const p of ['python3', 'Python', 'python3.12', 'node', 'curl', 'bash', 'nc', 'powershell.exe', '/usr/bin/perl', 'osascript']) assert.ok(N.isRisky(p), p);
  for (const p of ['firefox', 'Safari', 'Claude Helper', 'chrome', 'Slack', 'sshd', 'pythonista', 'nodemon', null, '']) assert.ok(!N.isRisky(p), String(p));
});

// ---- baseline ----
const MIN = 60000;

test('baseline: nothing is "new" during the learning window, everything seen then is "known" after', () => {
  const b = new Baseline({ learnMs: 10 * MIN, now: 0 });
  assert.equal(b.observe('python', 'pypi.org', 1 * MIN), 'learning');
  assert.equal(b.observe('python', 'pypi.org', 2 * MIN), 'learning');
  assert.equal(b.observe('python', 'pypi.org', 11 * MIN), 'known');
  assert.equal(b.observe('python', 'evil-c2.example', 12 * MIN), 'new');
  assert.equal(b.observe('python', 'evil-c2.example', 13 * MIN), 'known'); // flagged once, then part of the baseline
});

test('baseline: destinations are per process', () => {
  const b = new Baseline({ learnMs: 0, now: 0 });
  assert.equal(b.observe('curl', 'github.com', 1), 'new');
  assert.equal(b.observe('python', 'github.com', 1), 'new');
  assert.equal(b.observe('curl', 'github.com', 2), 'known');
});

test('baseline: ignores empty input and caps growth', () => {
  const b = new Baseline({ learnMs: 0, now: 0 });
  assert.equal(b.observe(null, 'x', 1), 'known');
  assert.equal(b.observe('p', '', 1), 'known');
  for (let i = 0; i < 2100; i++) b.observe('p', 'd' + i, 1);
  assert.equal(b.procs.get('p').size, 2000);
  for (let i = 0; i < 600; i++) b.observe('proc' + i, 'd', 1);
  assert.ok(b.procs.size <= 500);
});

test('baseline: survives save/load, and a corrupt file starts a fresh learning window', () => {
  const fs = require('node:fs'), os = require('node:os'), path = require('node:path');
  const f = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'nw-')), 'baseline.json');
  const b = new Baseline({ learnMs: 0, now: 0 });
  b.observe('curl', 'example.com', 1);
  b.save(f);
  const c = Baseline.load(f);
  assert.equal(c.observe('curl', 'example.com', Date.now()), 'known');
  assert.equal(c.observe('curl', 'other.example', Date.now()), 'new');
  fs.writeFileSync(f, '{not json');
  const d = Baseline.load(f, { learnMs: 5 * MIN });
  assert.ok(d.learning());
  assert.equal(d.procs.size, 0);
});
