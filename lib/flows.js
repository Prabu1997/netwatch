// Flow table: remembers what App-ID learned about each 5-tuple, from packets seen by the capture process.
const os = require('os');
const { spawn } = require('child_process');
const { PcapStream, inspectPayload, classify } = require('./appid');
const { normIp } = require('./ip');

const TTL = 10 * 60 * 1000;
const MAX_CONNS = 20000; // bound memory against floods (port scans, UDP storms)
const key = (proto, aIp, aPort, bIp, bPort) => {
  const a = `${aIp}:${aPort}`, b = `${bIp}:${bPort}`;
  return proto + '|' + (a < b ? a + '|' + b : b + '|' + a); // direction-independent
};
const connKey = (proto, lip, lport, rip, rport) => `${proto}|${normIp(lip)}|${lport}|${normIp(rip)}|${rport}`;

// This machine's own addresses, so a packet's direction can be told. Refreshed lazily: interfaces come and go.
function localChecker() {
  let set = new Set(), at = 0;
  return ip => {
    if (Date.now() - at > 30000) {
      at = Date.now(); set = new Set();
      for (const list of Object.values(os.networkInterfaces())) for (const a of list || []) set.add(normIp(a.address));
    }
    return set.has(normIp(ip));
  };
}

// Multicast/broadcast are not "connections to a server": mDNS, SSDP, DHCP would flood the session list.
const isGroupAddr = ip => /^(22[4-9]|2[3-5]\d)\./.test(ip) || ip === '255.255.255.255' || /^ff/i.test(ip);

class FlowTable {
  constructor({ isLocal } = {}) {
    this.flows = new Map(); this.names = new Map();
    this.conns = new Map(); // every outbound flow seen on the wire, whether or not it revealed an identity
    this.isLocal = isLocal || localChecker();
  }

  // Record that this machine opened (or is using) an outbound flow. Only flows we saw *start* are recorded:
  // TCP by its SYN, UDP by its first outbound packet. Inbound-initiated traffic (scans, probes) is never tracked.
  track(p, now) {
    if (p.proto !== 'tcp' && p.proto !== 'udp') return;
    const srcLocal = this.isLocal(p.src), dstLocal = this.isLocal(p.dst);
    if (srcLocal === dstLocal) return; // loopback, forwarded, or unrelated
    const lip = srcLocal ? p.src : p.dst, lport = srcLocal ? p.sport : p.dport;
    const rip = srcLocal ? p.dst : p.src, rport = srcLocal ? p.dport : p.sport;
    const k = connKey(p.proto, lip, lport, rip, rport);
    let c = this.conns.get(k);
    if (!c) {
      if (!srcLocal || this.conns.size >= MAX_CONNS || isGroupAddr(rip)) return;
      if (p.proto === 'tcp' && !((p.flags & 0x02) && !(p.flags & 0x10))) return; // not a connection start
      if (p.proto === 'udp' && (rport === 53 || rport === 5353 || rport === 123)) return; // one-shot lookups: pure noise as rows
      c = { proto: p.proto, lip, lport, rip, rport, first: now, last: now, pktsOut: 0, pktsIn: 0, bytesOut: 0, bytesIn: 0 };
      this.conns.set(k, c);
    }
    c.last = now;
    if (srcLocal) { c.pktsOut++; c.bytesOut += p.payload.length; } else { c.pktsIn++; c.bytesIn += p.payload.length; }
  }

  observe(p, now = Date.now()) {
    this.track(p, now);
    const id = inspectPayload(p);
    const k = key(p.proto, p.src, p.sport, p.dst, p.dport);
    let f = this.flows.get(k);
    if (!id && !f) return;
    if (!f) { f = {}; this.flows.set(k, f); }
    f.last = now;
    if (id) {
      Object.assign(f, id);
      Object.assign(f, classify({ ...f, proto: p.proto, rport: p.dport }));
      const n = id.sni || id.host; // remember which hostname this destination was contacted as
      if (n) this.names.set(p.dst, n);
    }
  }
  get(proto, lip, lport, rip, rport) { return this.flows.get(key(proto, lip, lport, rip, rport)) || null; }
  nameFor(ip) { return this.names.get(ip) || null; }
  expire(now = Date.now()) {
    for (const [k, f] of this.flows) if (now - f.last > TTL) this.flows.delete(k);
    for (const [k, c] of this.conns) if (now - c.last > TTL) this.conns.delete(k);
    if (this.names.size > 5000) this.names.clear(); // cheap bound; names are re-learned from the next handshake
  }
}

// Spawns `tcpdump -w -` (needs root) and feeds the table. Fails soft: returns {error} instead of throwing.
function startCapture(table, platform, { iface, log = console.log } = {}) {
  const state = { running: false, error: null, packets: 0 };
  let proc;
  try { proc = spawn('tcpdump', [...platform.captureArgs(iface), 'tcp or udp'], { stdio: ['ignore', 'pipe', 'pipe'] }); }
  catch (e) { state.error = String(e.message); return state; }
  const pcap = new PcapStream((p, t) => { state.packets++; table.observe(p, t); });
  proc.stdout.on('data', c => { try { pcap.push(c); } catch (e) { state.error = e.message; proc.kill(); } });
  let err = '';
  proc.stderr.on('data', d => { err += d; if (err.length > 2000) err = err.slice(-2000); });
  proc.on('spawn', () => { state.running = true; });
  proc.on('error', e => { state.running = false; state.error = e.code === 'ENOENT' ? 'tcpdump not installed' : e.message; });
  proc.on('exit', code => {
    state.running = false;
    if (code) { state.error = (/permission|not permitted|root/i.test(err) ? 'packet capture needs root' : err.split('\n').find(l => l.trim()) || 'tcpdump exited ' + code); log('capture stopped: ' + state.error); }
  });
  setInterval(() => table.expire(), 60000).unref();
  state.stop = () => proc.kill();
  return state;
}

module.exports = { FlowTable, startCapture, key, connKey };
