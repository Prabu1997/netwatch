// Flow table: remembers what App-ID learned about each 5-tuple, from packets seen by the capture process.
const { spawn } = require('child_process');
const { PcapStream, inspectPayload, classify } = require('./appid');

const TTL = 10 * 60 * 1000;
const key = (proto, aIp, aPort, bIp, bPort) => {
  const a = `${aIp}:${aPort}`, b = `${bIp}:${bPort}`;
  return proto + '|' + (a < b ? a + '|' + b : b + '|' + a); // direction-independent
};

class FlowTable {
  constructor() { this.flows = new Map(); this.names = new Map(); }
  observe(p, now = Date.now()) {
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
  expire(now = Date.now()) { for (const [k, f] of this.flows) if (now - f.last > TTL) this.flows.delete(k); }
}

// Spawns `tcpdump -w -` (needs root) and feeds the table. Fails soft: returns {error} instead of throwing.
function startCapture(table, platform, { iface, log = console.log } = {}) {
  const state = { running: false, error: null, packets: 0 };
  let proc;
  try { proc = spawn('tcpdump', [...platform.captureArgs(iface), 'tcp or udp port 53 or udp port 5353'], { stdio: ['ignore', 'pipe', 'pipe'] }); }
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

module.exports = { FlowTable, startCapture, key };
