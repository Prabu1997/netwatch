// Joins what the OS socket list says with what the packet capture saw. The socket list is polled, so it misses
// short-lived connections, and it shows UDP sockets (QUIC!) without a remote address. The capture sees both.
// Pure function: no I/O, so it is tested without root.
const { connKey } = require('./flows');

// Returns captured outbound flows that no socket row accounts for, each with the process that owns the local port
// when the socket list knows it (an unconnected UDP socket still reveals its owner by local port).
// `known` holds connKeys of sessions already created from the socket list, so a connection that has since closed
// is not shown a second time as a packet-only flow.
function packetOnly(conns, rows, now, { windowMs = 5000, known = new Set() } = {}) {
  const covered = new Set(known);
  const byPort = new Map();
  for (const r of rows) {
    if (r.rip && r.rip !== '*' && r.rport) covered.add(connKey(r.proto, r.lip, r.lport, r.rip, r.rport));
    const k = `${r.proto}|${r.lport}`;
    if (r.lport && (!byPort.has(k) || (!byPort.get(k).pid && r.pid))) byPort.set(k, r);
  }
  const out = [];
  for (const rec of conns.values()) {
    const ck = connKey(rec.proto, rec.lip, rec.lport, rec.rip, rec.rport);
    if (covered.has(ck)) continue;
    const owner = byPort.get(`${rec.proto}|${rec.lport}`) || null;
    out.push({ key: 'pkt|' + ck, rec, owner, live: now - rec.last < windowMs });
  }
  return out;
}

module.exports = { packetOnly };
