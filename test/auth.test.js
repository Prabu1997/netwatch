const test = require('node:test');
const assert = require('node:assert/strict');
const A = require('../lib/auth');
const S = require('../lib/safety');

const TOKEN = A.newToken();
const req = (o = {}) => ({ url: '/api/sessions', method: 'GET', socket: { remoteAddress: '127.0.0.1' },
  headers: { host: '127.0.0.1:8080', 'x-netwatch-token': TOKEN, ...(o.headers || {}) }, ...o, ...(o.headers ? { headers: { host: '127.0.0.1:8080', 'x-netwatch-token': TOKEN, ...o.headers } } : {}) });
const auth = (r, o = {}) => A.authorize(r, { token: TOKEN, ...o });

test('tokens are long, unique and url-safe', () => {
  const a = A.newToken(), b = A.newToken();
  assert.notEqual(a, b); assert.ok(a.length >= 30); assert.match(a, /^[\w-]+$/);
});

test('valid token via header or ?t= is accepted; missing/wrong/empty is not', () => {
  assert.equal(auth(req()).ok, true);
  assert.equal(auth(req({ url: '/events?t=' + TOKEN, headers: { 'x-netwatch-token': '' } })).ok, true);
  const no = auth(req({ headers: { 'x-netwatch-token': '' } }));
  assert.equal(no.ok, false); assert.equal(no.status, 401);
  assert.equal(auth(req({ headers: { 'x-netwatch-token': TOKEN + 'x' } })).ok, false);
  assert.equal(auth(req({ headers: { 'x-netwatch-token': TOKEN.slice(0, -1) } })).ok, false);
});

test('DNS rebinding: a foreign Host header is rejected even with the right token', () => {
  for (const host of ['evil.example', 'evil.example:8080', '127.0.0.1.evil.example', 'localhost.evil.example', '']) {
    const r = auth(req({ headers: { host } }));
    assert.equal(r.ok, false, host); assert.equal(r.status, 403);
  }
  for (const host of ['127.0.0.1', '127.0.0.1:8080', 'localhost:9', '[::1]:8080']) assert.equal(auth(req({ headers: { host } })).ok, true, host);
});

test('CSRF: a cross-site Origin is rejected; same-origin and no Origin are fine', () => {
  assert.equal(auth(req({ headers: { origin: 'https://evil.example' } })).ok, false);
  assert.equal(auth(req({ headers: { origin: 'null' } })).ok, false);
  assert.equal(auth(req({ headers: { origin: 'http://127.0.0.1:8080' } })).ok, true);
  assert.equal(auth(req()).ok, true);
});

test('non-loopback peers are rejected unless explicitly allowed', () => {
  const far = req({ socket: { remoteAddress: '192.168.1.50' } });
  assert.equal(auth(far).ok, false);
  assert.equal(auth(far, { allowRemote: true }).ok, true);
  assert.equal(auth(req({ socket: { remoteAddress: '::1' } })).ok, true);
  assert.equal(auth(req({ socket: { remoteAddress: '::ffff:127.0.0.1' } })).ok, true);
});

test('state-changing calls also need the X-Netwatch header', () => {
  assert.equal(auth(req({ method: 'POST' }), { mutating: true }).ok, false);
  assert.equal(auth(req({ method: 'POST', headers: { 'x-netwatch': '1' } }), { mutating: true }).ok, true);
});

test('the static page is public but still host/origin/peer checked', () => {
  const noTok = { headers: { host: '127.0.0.1:8080' }, url: '/', socket: { remoteAddress: '127.0.0.1' } };
  assert.equal(A.authorize(noTok, { token: TOKEN, public: true }).ok, true);
  assert.equal(A.authorize({ ...noTok, headers: { host: 'evil.example' } }, { token: TOKEN, public: true }).ok, false);
});

test('rate limiter: allows N per window, then blocks, then recovers', () => {
  const lim = A.limiter(3, 1000);
  assert.deepEqual([lim(0), lim(1), lim(2), lim(3)], [true, true, true, false]);
  assert.equal(lim(1001), true);
});

// ---- safety: addresses that must never be blocked ----
test('safety: private ranges, junk and configured resolvers are protected; ordinary public IPs are not', () => {
  S._reset();
  S.protectedSet(Date.now(), () => ['9.9.9.9', '2606:4700:4700::1111']);
  for (const ip of ['10.1.2.3', '192.168.0.1', '127.0.0.1', '::1', 'fe80::1', 'not-an-ip', '0.0.0.0', '9.9.9.9', '2606:4700:4700:0:0:0:0:1111']) assert.equal(S.isProtectedIp(ip), true, ip);
  for (const ip of ['8.8.8.8', '203.0.113.9', '1.1.1.1']) assert.equal(S.isProtectedIp(ip), false, ip);
  S._reset();
});
