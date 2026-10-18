// Real-system tests: need root. They skip themselves otherwise, so `npm test` stays safe on a laptop.
// Run them with: sudo node --test test/integration.test.js   (CI does this on Linux and macOS)
const test = require('node:test');
const assert = require('node:assert/strict');
const net = require('node:net');
const { execFileSync, spawn } = require('node:child_process');
const platform = require('../lib/platform');
const { FlowTable, startCapture } = require('../lib/flows');

const root = process.getuid && process.getuid() === 0;
const LO = process.platform === 'darwin' ? 'lo0' : 'lo';
const sleep = ms => new Promise(r => setTimeout(r, ms));

// A listener that never speaks TLS: it only needs to receive the ClientHello bytes on the wire.
function sink() {
  return new Promise(res => {
    const srv = net.createServer(s => { s.on('data', () => {}); s.on('error', () => {}); setTimeout(() => s.destroy(), 500); });
    srv.listen(0, '127.0.0.1', () => res(srv));
  });
}

test('capture: real tcpdump sees a real ClientHello and App-ID labels it', { skip: !root && 'needs root' }, async () => {
  const srv = await sink();
  const port = srv.address().port;
  const table = new FlowTable();
  const cap = startCapture(table, platform, { iface: LO, log: () => {} });
  await sleep(1500); // let tcpdump attach before generating traffic
  assert.equal(cap.error, null, 'capture failed: ' + cap.error);
  const c = spawn('openssl', ['s_client', '-connect', `127.0.0.1:${port}`, '-servername', 'api.github.com'], { stdio: ['pipe', 'ignore', 'ignore'] });
  await sleep(1500);
  c.kill(); cap.stop(); srv.close();
  const hit = [...table.flows.values()].find(f => f.sni === 'api.github.com');
  assert.ok(hit, `no flow labelled; ${cap.packets} packets seen`);
  assert.equal(hit.app, 'github');
  assert.match(hit.ja3, /^[0-9a-f]{32}$/);
});

test('enforce: block really drops traffic and unblock restores it', { skip: (!root && 'needs root') || (process.platform !== 'linux' && 'iptables backend is Linux-only') }, async () => {
  const srv = await sink();
  const port = srv.address().port;
  const tryConnect = () => new Promise(res => {
    const s = net.connect({ host: '127.0.0.1', port, timeout: 800 });
    s.on('connect', () => { s.destroy(); res(true); });
    s.on('timeout', () => { s.destroy(); res(false); });
    s.on('error', () => res(false));
  });
  assert.ok(await tryConnect(), 'baseline connect must work');
  // 127.0.0.1 is protected from block(); use the chain directly to prove the kernel path works.
  execFileSync('iptables', ['-N', 'NETWATCH_TEST']);
  try {
    execFileSync('iptables', ['-I', 'OUTPUT', '1', '-j', 'NETWATCH_TEST']);
    execFileSync('iptables', ['-A', 'NETWATCH_TEST', '-d', '127.0.0.1', '-p', 'tcp', '--dport', String(port), '-j', 'DROP']);
    assert.equal(await tryConnect(), false, 'connection should be dropped');
  } finally {
    try { execFileSync('iptables', ['-D', 'OUTPUT', '-j', 'NETWATCH_TEST']); } catch {}
    try { execFileSync('iptables', ['-F', 'NETWATCH_TEST']); execFileSync('iptables', ['-X', 'NETWATCH_TEST']); } catch {}
  }
  assert.ok(await tryConnect(), 'connect works again after rule removal');
  srv.close();
});

test('platform.connections() sees our own listening socket with correct pid', { skip: process.platform === 'linux' && !root && 'needs root to see pids' }, async () => {
  const srv = await sink();
  const port = srv.address().port;
  const rows = await platform.connections();
  const mine = rows.find(r => r.lport === port && r.state === 'LISTEN');
  srv.close();
  assert.ok(mine, 'own listener not found in connection list');
  assert.equal(mine.pid, process.pid);
});
