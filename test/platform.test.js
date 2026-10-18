const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const linux = require('../lib/platform/linux');
const darwin = require('../lib/platform/darwin');
const pf = require('../lib/enforce/pf');

test('linux: parse ss -tunapH output, v4 + v6 + shared socket', () => {
  const out = [
    'tcp   ESTAB  0  0  192.168.1.10:51234  140.82.112.4:443  users:(("curl",pid=4242,fd=5))',
    'tcp   ESTAB  0  0  [2001:db8::1]:40000  [2606:4700::1]:443  users:(("firefox",pid=99,fd=3))',
    'tcp   ESTAB  0  0  10.0.0.5:4444  203.0.113.7:9001  users:(("python3",pid=7,fd=3),("bash",pid=8,fd=3))',
    'udp   UNCONN 0  0  *%lo:53  0.0.0.0:*',
  ].join('\n');
  const rows = linux.parseSS(out);
  assert.equal(rows.length, 4);
  assert.deepEqual([rows[0].rip, rows[0].rport, rows[0].proc, rows[0].pid], ['140.82.112.4', 443, 'curl', 4242]);
  assert.deepEqual([rows[1].lip, rows[1].rip], ['2001:db8::1', '2606:4700::1']);
  assert.equal(rows[2].proc, 'bash'); // shell-like holder preferred as primary
  assert.equal(rows[3].pid, null);
});

test('darwin: parse lsof -F output', () => {
  const out = [
    'p501', 'cSafari', 'f22', 'PTCP', 'n192.168.1.5:50123->17.253.144.10:443', 'TST=ESTABLISHED',
    'f23', 'PTCP', 'n*:8080', 'TST=LISTEN',
    'p777', 'cmDNSResponder', 'f5', 'PUDP', 'n*:5353',
    'f6', 'PTCP', 'n[2001:db8::2]:50000->[2606:4700::6810]:443', 'TST=ESTABLISHED',
  ].join('\n');
  const rows = darwin.parseLsof(out);
  assert.equal(rows.length, 4);
  assert.deepEqual([rows[0].proc, rows[0].pid, rows[0].state, rows[0].rip, rows[0].rport, rows[0].proto], ['Safari', 501, 'ESTAB', '17.253.144.10', 443, 'tcp']);
  assert.deepEqual([rows[1].state, rows[1].lport], ['LISTEN', 8080]);
  assert.deepEqual([rows[2].proc, rows[2].state, rows[2].proto], ['mDNSResponder', 'UNCONN', 'udp']);
  assert.deepEqual([rows[3].lip, rows[3].rip], ['2001:db8::2', '2606:4700::6810']);
});

test('darwin: parse ps output', () => {
  assert.deepEqual(darwin.parsePs('  alice  1 /usr/bin/ssh -p 22 host\n'), { exe: '/usr/bin/ssh', cmd: '/usr/bin/ssh -p 22 host', user: 'alice', ppid: 1, deleted: false });
  assert.equal(darwin.parsePs(''), null);
});

test('darwin: capture never uses "-i any" (Apple tcpdump rejects it) and finds the default interface', () => {
  assert.equal(darwin.parseDefaultIface('   route to: default\ndestination: default\n  interface: en0\n      flags: <UP,GATEWAY>'), 'en0');
  assert.equal(darwin.parseDefaultIface('nothing'), null);
  const args = darwin.captureArgs();
  assert.notEqual(args[args.indexOf('-i') + 1], 'any');
  assert.equal(darwin.captureArgs('utun3')[1], 'utun3');
});

test('pf: anchor rules and main-ruleset hook are correct and idempotent', () => {
  assert.equal(pf.rules([]), '');
  assert.equal(pf.rules(['1.2.3.4', '2001:db8::1']), 'table <netwatch_blocked> persist { 1.2.3.4, 2001:db8::1 }\nblock drop out quick to <netwatch_blocked>\n');
  const once = pf.MAIN('scrub-anchor "com.apple/*"\nanchor "com.apple/*"\n');
  assert.ok(once.endsWith('anchor "netwatch"\n'));
  assert.equal(pf.MAIN(once), once);
});

test('backend selection follows NETWATCH_PLATFORM', () => {
  const q = p => execFileSync(process.execPath, ['-e', "console.log(require('./lib/platform').name, typeof require('./lib/enforce').rules)"],
    { cwd: path.join(__dirname, '..'), env: { ...process.env, NETWATCH_PLATFORM: p } }).toString().trim();
  assert.equal(q('darwin'), 'darwin function');
  assert.equal(q('linux'), 'linux undefined');
});
