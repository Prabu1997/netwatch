// IP helpers shared by the socket lister and the packet decoder. The two print IPv6 differently
// (compression, case, zone ids), so anything that compares addresses must go through normIp().
const net = require('net');

// Canonical key: IPv4 as-is, IPv6 expanded to 8 lowercase zero-padded groups, IPv4-mapped IPv6 folded to IPv4.
function normIp(ip) {
  if (typeof ip !== 'string' || !ip) return ip;
  ip = ip.replace(/%.*$/, '').replace(/^\[|\]$/g, '').toLowerCase();
  if (!ip.includes(':')) return ip;
  const mapped = ip.match(/^(?:0{0,4}:){0,5}(?:ffff:)(\d+\.\d+\.\d+\.\d+)$/) || ip.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return mapped[1];
  let tail = [];
  const v4 = ip.match(/^(.*:)(\d+\.\d+\.\d+\.\d+)$/); // trailing dotted quad
  if (v4) {
    const o = v4[2].split('.').map(Number);
    ip = v4[1] + ((o[0] << 8) | o[1]).toString(16) + ':' + ((o[2] << 8) | o[3]).toString(16);
  }
  const [h, t = null] = ip.split('::');
  const head = h ? h.split(':') : [];
  tail = t ? t.split(':') : [];
  if (t === null) return head.length === 8 ? head.map(g => g.padStart(4, '0')).join(':') : ip;
  const fill = Array(Math.max(0, 8 - head.length - tail.length)).fill('0');
  return [...head, ...fill, ...tail].map(g => g.padStart(4, '0')).join(':');
}

// RFC 5952 text form (what `ss`/`lsof` print): lowercase, no leading zeros, longest zero run (>=2 groups) as "::".
function formatV6(groups) {
  const g = groups.map(n => n.toString(16));
  let best = -1, bestLen = 1, cur = -1, len = 0;
  for (let i = 0; i <= 8; i++) {
    if (i < 8 && groups[i] === 0) { if (cur < 0) cur = i; len++; }
    else { if (len > bestLen) { best = cur; bestLen = len; } cur = -1; len = 0; }
  }
  if (best < 0) return g.join(':');
  return g.slice(0, best).join(':') + '::' + g.slice(best + bestLen).join(':');
}

const isPrivate = ip =>
  /^(10\.|127\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|::1$|fe80:|f[cd][0-9a-f]{2}:)/i.test(ip) || ip === '*' || ip === '0.0.0.0' || ip === '::';

module.exports = { normIp, formatV6, isPrivate, isIP: net.isIP };
