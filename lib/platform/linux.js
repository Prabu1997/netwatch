// Linux backend: `ss` for sockets, /proc for process details.
const fs = require('fs');
const { execFile } = require('child_process');

const SHELLS = new Set(['sh', 'bash', 'dash', 'zsh', 'ash', 'ksh', 'fish', 'nc', 'ncat', 'netcat', 'socat', 'telnet']);

function splitAddr(a) {
  a = a.replace(/%[^:\]]+/, ''); // strip %iface
  const i = a.lastIndexOf(':');
  return { ip: a.slice(0, i).replace(/^\[|\]$/g, ''), port: a.slice(i + 1) };
}

function parseSS(out) {
  const rows = [];
  for (const line of out.split('\n')) {
    const f = line.trim().split(/\s+/);
    if (f.length < 6) continue;
    const [proto, state, , , local, remote] = f;
    const holders = [...line.matchAll(/\("([^"]*)",pid=(\d+)/g)].map(h => ({ name: h[1], pid: +h[2] }));
    // a socket can be shared by several processes (fork/exec): prefer a shell-like holder as the primary
    const m = holders.find(h => SHELLS.has(h.name)) || holders[0];
    const l = splitAddr(local), r = splitAddr(remote);
    rows.push({ proto, state, lip: l.ip, lport: +l.port || 0, rip: r.ip, rport: +r.port || 0,
      proc: m ? m.name : null, pid: m ? m.pid : null, holders: holders.map(h => h.name) });
  }
  return rows;
}

const connections = () => new Promise(res =>
  execFile('ss', ['-tunapH'], { maxBuffer: 16e6 }, (e, out) => res(e ? [] : parseSS(out))));

async function procInfo(pid) {
  const info = { exe: null, cmd: null, user: null, ppid: null, deleted: false };
  try { info.exe = fs.readlinkSync(`/proc/${pid}/exe`); } catch {}
  if (info.exe && info.exe.endsWith(' (deleted)')) { info.deleted = true; info.exe = info.exe.replace(' (deleted)', ''); }
  try { info.cmd = fs.readFileSync(`/proc/${pid}/cmdline`, 'utf8').replace(/\0/g, ' ').trim().slice(0, 200); } catch {}
  try {
    const s = fs.readFileSync(`/proc/${pid}/status`, 'utf8');
    info.ppid = +(s.match(/PPid:\s+(\d+)/) || [])[1] || null;
    const uid = (s.match(/Uid:\s+(\d+)/) || [])[1];
    info.user = uid;
    try {
      const pw = fs.readFileSync('/etc/passwd', 'utf8').split('\n').find(l => l.split(':')[2] === uid);
      if (pw) info.user = pw.split(':')[0];
    } catch {}
  } catch {}
  return info;
}

module.exports = { name: 'linux', SHELLS, parseSS, connections, procInfo, captureArgs: iface => ['-i', iface || 'any', '-U', '-w', '-', '-s', '512'] };
