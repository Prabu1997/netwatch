// Starts the real server and attacks it over HTTP the way a hostile local process or web page would.
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const net = require('node:net');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');

const TOKEN = 'test-token-0123456789abcdefghij';

const freePort = () => new Promise(res => { const s = net.createServer().listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => res(p)); }); });

async function start(env = {}) {
  const port = await freePort();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nw-srv-')); fs.chmodSync(dir, 0o700);
  const p = spawn(process.execPath, [path.join(__dirname, '..', 'server.js')], {
    env: { ...process.env, PORT: String(port), DATA_DIR: dir, CAPTURE: '0', POLL_MS: '500', ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
  let out = '';
  p.stdout.on('data', d => out += d); p.stderr.on('data', d => out += d);
  for (let i = 0; i < 100 && !/netwatch on http/.test(out); i++) await new Promise(r => setTimeout(r, 100));
  assert.match(out, /netwatch on http/, 'server did not start: ' + out);
  return { port, dir, p, out: () => out, stop: () => p.kill() };
}

const call = (port, { method = 'GET', url = '/', headers = {}, body } = {}) => new Promise((res, rej) => {
  const r = http.request({ host: '127.0.0.1', port, method, path: url, headers: { host: `127.0.0.1:${port}`, ...headers } }, resp => {
    let b = ''; resp.on('data', d => b += d); resp.on('end', () => res({ status: resp.statusCode, headers: resp.headers, body: b }));
  });
  r.on('error', rej); if (body) r.write(body); r.end();
});
const authed = { 'x-netwatch-token': TOKEN };

test('API access control, over real HTTP', async t => {
  const s = await start({ NETWATCH_TOKEN: TOKEN });
  t.after(s.stop);

  await t.test('page is public and framed-protected; data is not public', async () => {
    const page = await call(s.port);
    assert.equal(page.status, 200); assert.match(page.body, /Netwatch/);
    assert.equal(page.headers['x-frame-options'], 'DENY');
    assert.match(page.headers['content-security-policy'], /frame-ancestors 'none'/);
    for (const u of ['/api/sessions', '/events', '/api/ping']) {
      const r = await call(s.port, { url: u });
      assert.equal(r.status, 401, u);
      assert.ok(!/sessions|proc/.test(r.body), 'leaked data on ' + u);
    }
  });

  await t.test('wrong token is rejected; right token (header or ?t=) works', async () => {
    assert.equal((await call(s.port, { url: '/api/sessions', headers: { 'x-netwatch-token': 'nope' } })).status, 401);
    const ok = await call(s.port, { url: '/api/sessions', headers: authed });
    assert.equal(ok.status, 200);
    const j = JSON.parse(ok.body);
    assert.ok(Array.isArray(j.sessions)); assert.ok(Array.isArray(j.integrity)); assert.equal(typeof j.baseline.learning, 'boolean');
    assert.equal((await call(s.port, { url: '/api/ping?t=' + TOKEN })).status, 200);
  });

  await t.test('DNS rebinding and cross-site requests are refused even with a valid token', async () => {
    assert.equal((await call(s.port, { url: '/api/sessions', headers: { ...authed, host: 'evil.example' } })).status, 403);
    assert.equal((await call(s.port, { url: '/api/sessions', headers: { ...authed, origin: 'https://evil.example' } })).status, 403);
    assert.equal((await call(s.port, { method: 'POST', url: '/api/block', headers: { ...authed, origin: 'https://evil.example', 'x-netwatch': '1' }, body: '{"ip":"203.0.113.9"}' })).status, 403);
  });

  await t.test('block/unblock: needs the header, validates input, refuses protected addresses', async () => {
    const h = { ...authed, 'x-netwatch': '1', 'content-type': 'application/json' };
    assert.equal((await call(s.port, { method: 'POST', url: '/api/block', headers: authed, body: '{"ip":"203.0.113.9"}' })).status, 403);
    const priv = await call(s.port, { method: 'POST', url: '/api/block', headers: h, body: '{"ip":"192.168.1.1"}' });
    assert.equal(priv.status, 400); assert.match(priv.body, /refusing/);
    assert.equal((await call(s.port, { method: 'POST', url: '/api/block', headers: h, body: 'not json' })).status, 400);
    assert.equal((await call(s.port, { method: 'POST', url: '/api/block', headers: h, body: '{"ip":"a;rm -rf /"}' })).status, 400);
    assert.equal((await call(s.port, { method: 'POST', url: '/api/nothing', headers: h, body: '{}' })).status, 404);
  });

  await t.test('stream works with a token', async () => {
    const first = await new Promise((res, rej) => {
      const r = http.get({ host: '127.0.0.1', port: s.port, path: '/events?t=' + TOKEN, headers: { host: `127.0.0.1:${s.port}` } }, resp => {
        resp.once('data', d => { r.destroy(); res({ status: resp.statusCode, chunk: String(d) }); });
      });
      r.on('error', rej);
    });
    assert.equal(first.status, 200); assert.match(first.chunk, /^data: \{/);
  });

  await t.test('rate limit: a flood of block requests is cut off', async () => {
    const h = { ...authed, 'x-netwatch': '1', 'content-type': 'application/json' };
    const codes = [];
    for (let i = 0; i < 30; i++) codes.push((await call(s.port, { method: 'POST', url: '/api/unblock', headers: h, body: '{"ip":"203.0.113.9"}' })).status);
    assert.ok(codes.includes(429), codes.join(','));
  });
});

test('token is generated, persisted privately, and reused after a restart', { skip: process.platform === 'win32' }, async () => {
  const a = await start();
  const dir = a.dir;
  const file = path.join(dir, 'api-token');
  const printed = a.out().match(/#t=([\w-]+)/)[1];
  assert.ok(printed.length >= 30);
  assert.equal(fs.readFileSync(file, 'utf8').trim(), printed);
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  assert.equal((await call(a.port, { url: '/api/ping', headers: { 'x-netwatch-token': printed } })).status, 200);
  a.stop();
  await new Promise(r => a.p.on('exit', r));
  const port = await freePort();
  const b = spawn(process.execPath, [path.join(__dirname, '..', 'server.js')], { env: { ...process.env, PORT: String(port), DATA_DIR: dir, CAPTURE: '0' }, stdio: ['ignore', 'pipe', 'pipe'] });
  let out = ''; b.stdout.on('data', d => out += d);
  for (let i = 0; i < 100 && !/#t=/.test(out); i++) await new Promise(r => setTimeout(r, 100));
  b.kill();
  assert.equal(out.match(/#t=([\w-]+)/)[1], printed, 'token changed across restart');
});

test('a hostile symlink in the data folder cannot redirect the server\'s writes', { skip: process.platform === 'win32' }, async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nw-sym-')); fs.chmodSync(dir, 0o700);
  const victim = path.join(dir, 'victim.txt'); fs.writeFileSync(victim, 'PRECIOUS');
  fs.symlinkSync(victim, path.join(dir, 'api-token'));
  fs.symlinkSync(victim, path.join(dir, 'alerts.jsonl'));
  const port = await freePort();
  const p = spawn(process.execPath, [path.join(__dirname, '..', 'server.js')], { env: { ...process.env, PORT: String(port), DATA_DIR: dir, CAPTURE: '0' }, stdio: ['ignore', 'pipe', 'pipe'] });
  let out = ''; p.stdout.on('data', d => out += d); p.stderr.on('data', d => out += d);
  for (let i = 0; i < 100 && !/netwatch on http/.test(out); i++) await new Promise(r => setTimeout(r, 100));
  await new Promise(r => setTimeout(r, 800));
  p.kill();
  assert.equal(fs.readFileSync(victim, 'utf8'), 'PRECIOUS');
});
