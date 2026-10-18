const test = require('node:test');
const assert = require('node:assert/strict');
const dgram = require('node:dgram');
const { DomainList, parseList, valid } = require('../lib/domains');
const { DnsFilter, parseQuestion } = require('../lib/dnsfilter');
const { parseResolvConf, parseScutil, forwardable } = require('../lib/resolvers');
const P = require('../lib/policy');
const H = require('./helpers');

// ---- domain lists ----
test('parseList: plain lists and hosts-file lines, comments, junk, single labels, IPs', () => {
  const txt = ['# comment', '', 'Evil.Example.COM', '127.0.0.1\tbad.example.net', '0.0.0.0 worse.example.org # trailing', '*.wild.example.com',
    'com', 'localhost', '1.2.3.4', 'bad name.com', '-bad-.com', 'a'.repeat(64) + '.com', 'trailing.dot.example.'].join('\n');
  assert.deepEqual(parseList(txt).sort(), ['bad.example.net', 'evil.example.com', 'trailing.dot.example', 'wild.example.com', 'worse.example.org']);
});

test('valid: refuses TLDs and malformed names', () => {
  for (const d of ['example.com', 'a.b.c.example.co.uk', 'xn--bcher-kva.example']) assert.ok(valid(d), d);
  for (const d of ['com', '', 'a..b.com', '.com', 'exa mple.com', 'under_score.com', 'x'.repeat(254) + '.com']) assert.ok(!valid(d), d);
});

test('DomainList.match: subdomains yes, lookalikes and parents no, across multiple lists', () => {
  const l = new DomainList();
  l.set('custom', ['evil.com']); l.set('urlhaus', ['bad.example.net']);
  assert.deepEqual(l.match('evil.com'), { list: 'custom', domain: 'evil.com' });
  assert.deepEqual(l.match('A.B.Evil.com.'), { list: 'custom', domain: 'evil.com' });
  assert.deepEqual(l.match('x.bad.example.net'), { list: 'urlhaus', domain: 'bad.example.net' });
  assert.equal(l.match('notevil.com'), null);
  assert.equal(l.match('evil.com.attacker.org'), null);
  assert.equal(l.match('example.net'), null);   // the parent of a listed name is not listed
  assert.equal(l.match(''), null); assert.equal(l.match(null), null);
  assert.equal(l.size(), 2);
});

// ---- policy: domain field ----
test('policy: domain rules match name and subdomains only, and never a flow with no name', () => {
  const rule = { name: 'no-ads', action: 'deny', domain: ['ads.example.com'] };
  const ev = ctx => P.evaluate([rule], { proto: 'tcp', rip: '1.2.3.4', rport: 443, external: true, ...ctx }).action;
  assert.equal(ev({ domain: 'ads.example.com' }), 'deny');
  assert.equal(ev({ domain: 'x.ads.example.com' }), 'deny');
  assert.equal(ev({ domain: 'notads.example.com' }), 'allow');
  assert.equal(ev({ domain: 'example.com' }), 'allow');
  assert.equal(ev({}), 'allow');
});

test('policy.validate: domain field must be an array of real names', () => {
  assert.deepEqual(P.validate([{ name: 'a', action: 'deny', domain: ['example.com', '*.example.org'] }]), []);
  assert.ok(P.validate([{ name: 'a', action: 'deny', domain: ['com'] }]).length >= 1);
  assert.ok(P.validate([{ name: 'a', action: 'deny', domain: 'example.com' }]).length >= 1);
});

// ---- resolver discovery ----
test('resolvers: parse resolv.conf and scutil, drop loopback so the filter never forwards to itself', () => {
  assert.deepEqual(parseResolvConf('# nameserver 8.8.8.8\nnameserver 192.168.1.1\nnameserver fe80::1%en0\nsearch lan'), ['192.168.1.1', 'fe80::1']);
  const scutil = 'resolver #1\n  nameserver[0] : 192.168.1.1\n  nameserver[1] : 2001:4860:4860::8888\nresolver #2\n  nameserver[0] : 127.0.0.1\n';
  assert.deepEqual(parseScutil(scutil), ['192.168.1.1', '2001:4860:4860::8888', '127.0.0.1']);
  assert.deepEqual(forwardable(['127.0.0.1', '::1', '192.168.1.1', '0.0.0.0']), ['192.168.1.1']);
});

// ---- the DNS filter, end to end over real UDP sockets ----
const query = name => H.dnsQuery(name);
const rcode = b => b[3] & 0x0f;

function fakeUpstream({ silent = false } = {}) {
  return new Promise(res => {
    const s = dgram.createSocket('udp4'); const seen = [];
    s.on('message', (m, r) => {
      seen.push(m); if (silent) return;
      const ans = Buffer.concat([m, Buffer.from([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34])]); // one A record
      ans[2] |= 0x80; ans[7] = 1;
      s.send(ans, r.port, r.address);
    });
    s.bind(0, '127.0.0.1', () => res({ port: s.address().port, seen, close: () => s.close() }));
  });
}
const ask = (port, pkt, wait = 1500) => new Promise(res => {
  const c = dgram.createSocket('udp4'); const t = setTimeout(() => { c.close(); res(null); }, wait);
  c.on('message', m => { clearTimeout(t); c.close(); res(m); });
  c.send(pkt, port, '127.0.0.1');
});

async function setup(opts = {}) {
  const up = await fakeUpstream(opts);
  const decisions = [];
  const deny = new Set(['blocked.example.com']);
  const f = new DnsFilter({ decide: n => { const parts = n.split('.'); for (let i = 0; i < parts.length - 1; i++) if (deny.has(parts.slice(i).join('.'))) return { action: 'deny', why: 'test' }; return { action: 'allow' }; },
    upstreams: () => [{ host: '127.0.0.1', port: up.port }], timeoutMs: 400, onDecision: d => decisions.push(d), log: () => {} });
  assert.equal(await f.start(0, '127.0.0.1'), true);
  return { f, up, decisions, close: () => { f.stop(); up.close(); } };
}

test('dns filter: blocked name -> NXDOMAIN, upstream never asked; subdomain too', async () => {
  const s = await setup();
  try {
    for (const name of ['blocked.example.com', 'deep.sub.blocked.example.com']) {
      const r = await ask(s.f.port, query(name));
      assert.ok(r, name); assert.equal(rcode(r), 3, 'NXDOMAIN'); assert.ok(r[2] & 0x80, 'QR'); assert.ok(r[3] & 0x80, 'RA');
      assert.equal(r.readUInt16BE(0), 0x1234, 'same transaction id'); assert.equal(r.readUInt16BE(6), 0, 'no answers');
    }
    assert.equal(s.up.seen.length, 0, 'blocked queries must not leak upstream');
    assert.equal(s.f.stats.blocked, 2);
    assert.equal(s.decisions[0].action, 'deny');
  } finally { s.close(); }
});

test('dns filter: allowed name is forwarded and the upstream answer returned untouched', async () => {
  const s = await setup();
  try {
    const r = await ask(s.f.port, query('fine.example.org'));
    assert.ok(r); assert.equal(rcode(r), 0); assert.equal(r.readUInt16BE(6), 1);
    assert.deepEqual([...r.subarray(r.length - 4)], [93, 184, 216, 34]);
    assert.equal(s.up.seen.length, 1);
    assert.equal(s.f.stats.forwarded, 1);
  } finally { s.close(); }
});

test('dns filter: lookalike domains are not blocked', async () => {
  const s = await setup();
  try {
    for (const n of ['notblocked.example.com', 'blocked.example.com.evil.org', 'example.com']) assert.equal(rcode(await ask(s.f.port, query(n))), 0, n);
  } finally { s.close(); }
});

test('dns filter: dead upstream -> SERVFAIL, not a hang', async () => {
  const s = await setup({ silent: true });
  try {
    const t0 = Date.now();
    const r = await ask(s.f.port, query('fine.example.org'), 3000);
    assert.ok(r, 'client must get an answer'); assert.equal(rcode(r), 2);
    assert.ok(Date.now() - t0 < 2500);
    assert.equal(s.f.stats.failed, 1);
  } finally { s.close(); }
});

test('dns filter: garbage, responses and truncated packets are ignored and never crash it', async () => {
  const s = await setup();
  try {
    const resp = query('blocked.example.com'); resp[2] |= 0x80;
    for (const bad of [Buffer.alloc(0), Buffer.from('hello'), Buffer.alloc(40, 0xff), resp, query('blocked.example.com').subarray(0, 20)])
      assert.equal(await ask(s.f.port, bad, 150), null);
    assert.equal(rcode(await ask(s.f.port, query('still.works.org'))), 0, 'filter still alive');
  } finally { s.close(); }
});

test('parseQuestion: rejects compression pointers, oversize labels and non-standard opcodes', () => {
  assert.equal(parseQuestion(query('a.example.com')).name, 'a.example.com');
  const ptr = Buffer.from(query('a.example.com')); ptr[12] = 0xc0;
  assert.equal(parseQuestion(ptr), null);
  const op = Buffer.from(query('a.example.com')); op[2] |= 0x28; // opcode 5
  assert.equal(parseQuestion(op), null);
  assert.equal(parseQuestion(query('a'.repeat(63) + '.com')).name.length, 67);
});

test('dns filter reports a port conflict instead of crashing', async () => {
  const a = await setup();
  const b = new DnsFilter({ decide: () => ({ action: 'allow' }), upstreams: () => [], log: () => {} });
  try {
    assert.equal(await b.start(a.f.port, '127.0.0.1'), false);
    assert.match(b.error, /in use|EADDRINUSE|bind/i);
  } finally { a.close(); }
});
