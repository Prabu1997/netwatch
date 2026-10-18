const test = require('node:test');
const assert = require('node:assert/strict');
const P = require('../lib/policy');

const ctx = (o = {}) => ({ proto: 'tcp', app: 'ssl', proc: 'curl', user: 'alice', rip: '203.0.113.9', rport: 443, cc: 'US', external: true, feeds: [], ...o });

test('first match wins; default applies when nothing matches', () => {
  const rules = [{ name: 'deny-bad', action: 'deny', dst: ['feed:any'] }, { name: 'allow-all', action: 'allow' }];
  assert.equal(P.evaluate(rules, ctx({ feeds: ['feodo'] })).rule, 'deny-bad');
  assert.equal(P.evaluate(rules, ctx()).rule, 'allow-all');
  assert.deepEqual(P.evaluate([], ctx()), { action: 'allow', rule: 'default', index: -1 });
  assert.equal(P.evaluate([], ctx(), 'deny').action, 'deny');
});

test('field matching: app, proc, user, port range, country, proto, external', () => {
  const r = x => P.evaluate([{ name: 'r', action: 'deny', ...x }], ctx()).action === 'deny';
  assert.ok(r({ app: ['ssl'] })); assert.ok(!r({ app: ['ssh'] }));
  assert.ok(r({ proc: ['curl'] })); assert.ok(!r({ proc: ['wget'] }));
  assert.ok(r({ user: ['alice'] })); assert.ok(!r({ user: ['bob'] }));
  assert.ok(r({ dport: ['400-500'] })); assert.ok(r({ dport: [443] })); assert.ok(!r({ dport: ['80-90'] }));
  assert.ok(r({ country: ['US', 'DE'] })); assert.ok(!r({ country: ['RU'] }));
  assert.ok(r({ proto: 'tcp' })); assert.ok(!r({ proto: 'udp' }));
  assert.ok(r({ external: true })); assert.ok(!r({ external: false }));
});

test('all conditions in a rule must hold (AND), list entries are OR', () => {
  const rule = { name: 'r', action: 'deny', app: ['ssh', 'ssl'], country: ['RU'] };
  assert.equal(P.evaluate([rule], ctx({ cc: 'US' })).action, 'allow');
  assert.equal(P.evaluate([rule], ctx({ cc: 'RU' })).action, 'deny');
});

test('CIDR matching: boundaries, /0, /32, exact, v6 exact only', () => {
  assert.ok(P.inCidr('10.1.2.3', '10.1.0.0/16')); assert.ok(!P.inCidr('10.2.0.1', '10.1.0.0/16'));
  assert.ok(P.inCidr('1.2.3.4', '0.0.0.0/0')); assert.ok(P.inCidr('1.2.3.4', '1.2.3.4/32')); assert.ok(!P.inCidr('1.2.3.5', '1.2.3.4/32'));
  assert.ok(P.inCidr('1.2.3.4', '1.2.3.4')); assert.ok(P.inCidr('2001:db8::1', '2001:db8::1')); assert.ok(!P.inCidr('2001:db8::2', '2001:db8::/32'));
});

test('feed matching by id and any; disabled rules are skipped', () => {
  const c = ctx({ feeds: ['tor'] });
  assert.equal(P.evaluate([{ name: 'a', action: 'alert', dst: ['feed:tor'] }], c).action, 'alert');
  assert.equal(P.evaluate([{ name: 'a', action: 'alert', dst: ['feed:feodo'] }], c).action, 'allow');
  assert.equal(P.evaluate([{ name: 'a', action: 'deny', disabled: true }], c).action, 'allow');
});

test('validate: catches the mistakes a hand-edited policy.json will contain', () => {
  assert.deepEqual(P.validate([{ name: 'ok', action: 'deny', dst: ['10.0.0.0/8', 'feed:tor'], dport: [443, '1-2'] }]), []);
  const errs = P.validate([{ action: 'drop', app: 'ssl', dst: ['999.1.1.1', '1.1.1.1/40'], dport: ['x'], bogus: 1 }, 5]);
  assert.ok(errs.length >= 7, errs.join('\n'));
  assert.deepEqual(P.validate('nope'), ['rules must be an array']);
});
