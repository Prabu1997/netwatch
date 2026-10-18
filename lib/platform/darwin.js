// macOS backend: `lsof` for sockets (field mode), `ps` for process details.
// Without root, lsof only reports your own processes; run with sudo to see everything.
const { execFile } = require('child_process');
const { SHELLS } = require('./linux');

const STATE = { ESTABLISHED: 'ESTAB', LISTEN: 'LISTEN', SYN_SENT: 'SYN-SENT', SYN_RECEIVED: 'SYN-RECV', CLOSE_WAIT: 'CLOSE-WAIT',
  FIN_WAIT_1: 'FIN-WAIT-1', FIN_WAIT_2: 'FIN-WAIT-2', TIME_WAIT: 'TIME-WAIT', CLOSING: 'CLOSING', LAST_ACK: 'LAST-ACK', CLOSED: 'CLOSE' };

function splitAddr(a) {
  if (!a || a === '*') return { ip: '*', port: 0 };
  const i = a.lastIndexOf(':');
  if (i < 0) return { ip: a, port: 0 };
  const port = a.slice(i + 1);
  return { ip: a.slice(0, i).replace(/^\[|\]$/g, ''), port: port === '*' ? 0 : +port || 0 };
}

// lsof -F output: one field per line, first char is the tag. p starts a process, f starts a file.
function parseLsof(out) {
  const rows = [];
  let proc = null, pid = null, cur = null;
  const flush = () => { if (cur && cur.name) rows.push(cur); cur = null; };
  for (const line of out.split('\n')) {
    if (!line) continue;
    const tag = line[0], val = line.slice(1);
    if (tag === 'p') { flush(); pid = +val; proc = null; }
    else if (tag === 'c') proc = val;
    else if (tag === 'f') { flush(); cur = { pid, proc }; }
    else if (!cur) continue;
    else if (tag === 'P') cur.proto = val.toLowerCase();
    else if (tag === 'n') cur.name = val;
    else if (tag === 'T' && val.startsWith('ST=')) cur.st = val.slice(3);
  }
  flush();
  return rows.map(c => {
    const [l, r] = c.name.split('->');
    const L = splitAddr(l), R = r ? splitAddr(r) : { ip: '*', port: 0 };
    const state = c.st ? (STATE[c.st] || c.st) : (c.proto === 'udp' ? 'UNCONN' : 'LISTEN');
    return { proto: c.proto, state: r && c.proto === 'udp' ? 'ESTAB' : state, lip: L.ip, lport: L.port, rip: R.ip, rport: R.port,
      proc: c.proc, pid: c.pid, holders: [c.proc] };
  });
}

const connections = () => new Promise(res =>
  execFile('lsof', ['-nP', '-i', '-FpcPnTf'], { maxBuffer: 32e6 }, (e, out) => res(out ? parseLsof(out) : [])));

function parsePs(out) {
  const m = out.trim().match(/^(\S+)\s+(\d+)\s+(.*)$/);
  if (!m) return null;
  const cmd = m[3];
  return { exe: cmd.split(' ')[0], cmd: cmd.slice(0, 200), user: m[1], ppid: +m[2], deleted: false };
}

const procInfo = pid => new Promise(res =>
  execFile('ps', ['-o', 'user=,ppid=,command=', '-p', String(pid)], (e, out) =>
    res((!e && parsePs(out)) || { exe: null, cmd: null, user: null, ppid: null, deleted: false })));

// Apple's tcpdump rejects `-i any` (PKTAP), so capture the default-route interface instead.
const parseDefaultIface = out => (out.match(/^\s*interface:\s*(\S+)/m) || [])[1] || null;
function defaultIface() {
  try { return parseDefaultIface(require('child_process').execFileSync('route', ['-n', 'get', 'default'], { encoding: 'utf8', timeout: 3000 })); } catch { return null; }
}

module.exports = { name: 'darwin', SHELLS, parseLsof, parsePs, parseDefaultIface, connections, procInfo,
  captureArgs: iface => ['-i', iface || defaultIface() || 'en0', '-U', '-w', '-', '-s', '512'] };
