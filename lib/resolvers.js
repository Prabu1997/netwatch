// Which DNS servers is this machine configured to use? macOS ignores /etc/resolv.conf for real lookups, so ask scutil.
const fs = require('fs');
const { execFileSync } = require('child_process');

const parseResolvConf = text => [...String(text).matchAll(/^\s*nameserver\s+(\S+)/gm)].map(m => m[1].replace(/%.*$/, ''));
const parseScutil = text => [...String(text).matchAll(/nameserver\[\d+\]\s*:\s*(\S+)/g)].map(m => m[1].replace(/%.*$/, ''));

function systemResolvers({ platform = process.platform, readFile = p => fs.readFileSync(p, 'utf8'), run = (c, a) => execFileSync(c, a, { encoding: 'utf8', timeout: 2000 }) } = {}) {
  const out = [];
  try { out.push(...parseResolvConf(readFile('/etc/resolv.conf'))); } catch {}
  if (platform === 'darwin') { try { out.push(...parseScutil(run('scutil', ['--dns']))); } catch {} }
  return [...new Set(out)];
}

// A resolver we can forward to: not ourselves, not loopback (that would loop back into this filter).
const forwardable = ips => ips.filter(ip => !/^127\./.test(ip) && ip !== '::1' && ip !== '0.0.0.0' && ip !== '::');

module.exports = { parseResolvConf, parseScutil, systemResolvers, forwardable };
