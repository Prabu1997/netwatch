// Addresses the firewall must never block, however it is asked (feed hit, policy, API call): blocking them would
// cut this machine off from the network or from the thing that resolves names for it.
const net = require('net');
const { normIp, isPrivate } = require('./ip');
const { systemResolvers } = require('./resolvers');

let cache = { at: 0, set: new Set() };

// Configured resolvers (resolv.conf, and scutil on macOS), plus NETWATCH_PROTECT=ip,ip.
function protectedSet(now = Date.now(), getResolvers = systemResolvers) {
  if (now - cache.at < 60000) return cache.set;
  const set = new Set();
  try { for (const ip of getResolvers()) set.add(normIp(ip)); } catch {}
  for (const ip of (process.env.NETWATCH_PROTECT || '').split(',').map(s => s.trim()).filter(Boolean)) set.add(normIp(ip));
  cache = { at: now, set };
  return set;
}

// Private/local ranges, anything that isn't an IP, and the protected set.
const isProtectedIp = ip => !net.isIP(ip) || isPrivate(ip) || /^0\.0\.0\.0$|^::$/.test(ip) || protectedSet().has(normIp(ip));

module.exports = { isProtectedIp, protectedSet, _reset: () => { cache = { at: 0, set: new Set() }; } };
