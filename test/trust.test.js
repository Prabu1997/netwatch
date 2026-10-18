const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const trust = require('../lib/trust');
const store = require('../lib/store');

delete process.env.NETWATCH_UNSAFE_CONFIG;
const posix = process.platform !== 'win32';
const me = posix ? process.getuid() : null;

function sandbox() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nw-trust-'));
  fs.chmodSync(dir, 0o700);
  return { dir, f: n => path.join(dir, n) };
}

test('own file in own private folder is trusted; missing files are fine', { skip: !posix }, () => {
  const s = sandbox();
  fs.writeFileSync(s.f('a'), 'x', { mode: 0o644 });
  assert.equal(trust.check(s.f('a')).ok, true);
  assert.equal(trust.check(s.f('nope')).missing, true);
  assert.equal(trust.check(s.f('nope'), { allowMissing: false }).ok, false);
});

test('group/world-writable files and folders are NOT trusted', { skip: !posix }, () => {
  const s = sandbox();
  fs.writeFileSync(s.f('loose'), 'x'); fs.chmodSync(s.f('loose'), 0o666);
  assert.match(trust.check(s.f('loose')).reason, /writable by group\/others/);
  fs.chmodSync(s.f('loose'), 0o644);
  assert.equal(trust.check(s.f('loose')).ok, true);
  fs.chmodSync(s.dir, 0o777);
  assert.match(trust.check(s.f('loose')).reason, /folder .* writable by group\/others/);
});

test('a symlink is NOT trusted, even to a harmless target', { skip: !posix }, () => {
  const s = sandbox();
  fs.writeFileSync(s.f('real'), 'x');
  fs.symlinkSync(s.f('real'), s.f('link'));
  assert.match(trust.check(s.f('link')).reason, /symlink/);
});

test('root server + user-owned folder (the real deployment mistake) is NOT trusted', { skip: !posix }, () => {
  const s = sandbox();
  fs.writeFileSync(s.f('policy.json'), '[]');
  const r = trust.check(s.f('policy.json'), { uid: 0 }); // simulate: process is root, files belong to an ordinary user
  if (me === 0) return; // already root: nothing to simulate
  assert.equal(r.ok, false);
  assert.match(r.reason, /not root/);
  assert.ok(trust.problems().some(p => p.file === s.f('policy.json') && /chown/.test(p.fix)));
});

test('problem list clears once the file is fixed', { skip: !posix }, () => {
  const s = sandbox();
  fs.writeFileSync(s.f('a'), 'x'); fs.chmodSync(s.f('a'), 0o666);
  trust.check(s.f('a'));
  assert.ok(trust.problems().some(p => p.file === s.f('a')));
  fs.chmodSync(s.f('a'), 0o644);
  trust.check(s.f('a'));
  assert.ok(!trust.problems().some(p => p.file === s.f('a')));
});

test('store.write refuses to follow a symlink: the victim file is untouched', { skip: !posix }, () => {
  const s = sandbox();
  const victim = s.f('victim'); fs.writeFileSync(victim, 'PRECIOUS');
  fs.symlinkSync(victim, s.f('alerts.jsonl'));
  assert.equal(store.write(s.f('alerts.jsonl'), 'overwritten'), false);
  assert.equal(store.append(s.f('alerts.jsonl'), 'appended'), false);
  assert.equal(fs.readFileSync(victim, 'utf8'), 'PRECIOUS');
});

test('store refuses a loose file: no truncation, no read', { skip: !posix }, () => {
  const s = sandbox();
  fs.writeFileSync(s.f('policy.json'), '[{"name":"x"}]'); fs.chmodSync(s.f('policy.json'), 0o666);
  assert.equal(store.read(s.f('policy.json')), null);
  assert.equal(store.write(s.f('policy.json'), 'wiped'), false);
  assert.equal(fs.readFileSync(s.f('policy.json'), 'utf8'), '[{"name":"x"}]');
});

test('store round trip, append, private mode, and folder creation', { skip: !posix }, () => {
  const s = sandbox();
  const f = path.join(s.dir, 'sub', 'x.json');
  assert.equal(store.write(f, '{"a":1}'), true);
  assert.equal(store.read(f), '{"a":1}');
  assert.equal(store.write(f, '{"a":2}'), true);       // shorter/longer rewrites must truncate properly
  assert.equal(store.read(f), '{"a":2}');
  assert.equal(store.append(s.f('log'), 'one\n'), true);
  assert.equal(store.append(s.f('log'), 'two\n'), true);
  assert.equal(store.read(s.f('log')), 'one\ntwo\n');
  assert.equal(store.write(s.f('secret'), 'tok', 0o600), true);
  assert.equal(fs.statSync(s.f('secret')).mode & 0o777, 0o600);
});

test('the override env var is an explicit escape hatch', { skip: !posix }, () => {
  const s = sandbox();
  fs.writeFileSync(s.f('a'), 'x'); fs.chmodSync(s.f('a'), 0o666);
  process.env.NETWATCH_UNSAFE_CONFIG = '1';
  try { assert.equal(trust.check(s.f('a')).ok, true); } finally { delete process.env.NETWATCH_UNSAFE_CONFIG; }
  assert.equal(trust.check(s.f('a')).ok, false);
});
