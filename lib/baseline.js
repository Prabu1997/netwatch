// Per-process baseline of who each program talks to. After a learning window, a first-ever destination is "new".
// Destinations are keyed by hostname when known (CDN IPs change; names do not), else by IP.
const store = require('./store');

const MAX_PROCS = 500, MAX_DESTS = 2000;

class Baseline {
  constructor({ learnMs = 10 * 60 * 1000, now = Date.now() } = {}) {
    this.procs = new Map();      // proc -> Set(dest)
    this.learnUntil = now + learnMs;
    this.dirty = false;
  }
  learning(now = Date.now()) { return now < this.learnUntil; }

  // Records the destination and says what it was: 'learning' (inside the window), 'new', or 'known'.
  observe(proc, dest, now = Date.now()) {
    if (!proc || !dest) return 'known';
    let set = this.procs.get(proc);
    if (!set) {
      if (this.procs.size >= MAX_PROCS) return this.learning(now) ? 'learning' : 'known';
      set = new Set(); this.procs.set(proc, set);
    }
    if (set.has(dest)) return this.learning(now) ? 'learning' : 'known';
    if (set.size < MAX_DESTS) { set.add(dest); this.dirty = true; }
    return this.learning(now) ? 'learning' : 'new';
  }

  toJSON() { return { learnUntil: this.learnUntil, procs: Object.fromEntries([...this.procs].map(([k, v]) => [k, [...v]])) }; }
  static from(obj) {
    const b = new Baseline({ learnMs: 0, now: 0 });
    b.learnUntil = +obj.learnUntil || 0;
    for (const [k, v] of Object.entries(obj.procs || {})) if (Array.isArray(v)) b.procs.set(k, new Set(v.slice(0, MAX_DESTS)));
    return b;
  }
  save(file) {
    if (!this.dirty) return;
    if (store.write(file, JSON.stringify(this))) this.dirty = false;
  }
  // An untrusted baseline file (editable by someone else while we run) is not believed: start a fresh learning window.
  static load(file, opts) {
    try { return Baseline.from(JSON.parse(store.read(file))); } catch { return new Baseline(opts); }
  }
}

module.exports = { Baseline };
