// Access control for the local HTTP API. Pure functions over plain request-like objects, so it is unit tested.
// Threats this addresses: another local user reading/driving the dashboard, a web page in your browser attacking
// 127.0.0.1 (CSRF, DNS rebinding). It cannot stop malware that runs as *you*: that can read anything you can.
const crypto = require('crypto');

const LOOPBACK = new Set(['127.0.0.1', '::1', '::ffff:127.0.0.1']);
const HOST_RE = /^(127\.0\.0\.1|localhost|\[::1\])(:\d+)?$/i;

const digest = s => crypto.createHash('sha256').update(String(s)).digest();
const newToken = () => crypto.randomBytes(24).toString('base64url');

function tokenFrom(req) {
  const h = req.headers['x-netwatch-token'];
  if (h) return String(h);
  try { return new URL(req.url, 'http://x').searchParams.get('t') || ''; } catch { return ''; }
}

function tokenOk(req, token) {
  const given = tokenFrom(req);
  return !!given && crypto.timingSafeEqual(digest(given), digest(token));
}

// DNS rebinding: a hostile site that re-points its name at 127.0.0.1 still sends its own Host header.
function hostOk(req) { return HOST_RE.test(req.headers.host || ''); }

// A browser sends Origin on cross-site requests; ours must come from the dashboard's own origin.
function originOk(req) {
  const o = req.headers.origin;
  if (!o) return true; // non-browser clients (curl) send none
  try { return HOST_RE.test(new URL(o).host); } catch { return false; }
}

function peerOk(req, allowRemote = false) {
  if (allowRemote) return true;
  const a = req.socket && req.socket.remoteAddress;
  return !!a && LOOPBACK.has(a);
}

// Sliding-window limiter for state-changing calls. A stolen or buggy client can't mass-block addresses.
function limiter(max = 20, windowMs = 60000) {
  const hits = [];
  return (now = Date.now()) => {
    while (hits.length && now - hits[0] > windowMs) hits.shift();
    if (hits.length >= max) return false;
    hits.push(now);
    return true;
  };
}

// -> { ok, status?, why? }
function authorize(req, { token, allowRemote = false, mutating = false, public: isPublic = false }) {
  if (!peerOk(req, allowRemote)) return { ok: false, status: 403, why: 'non-local peer' };
  if (!hostOk(req)) return { ok: false, status: 403, why: 'bad Host header' };
  if (!originOk(req)) return { ok: false, status: 403, why: 'cross-origin request' };
  if (isPublic) return { ok: true };
  if (!tokenOk(req, token)) return { ok: false, status: 401, why: 'missing or wrong token' };
  if (mutating && req.headers['x-netwatch'] !== '1') return { ok: false, status: 403, why: 'missing X-Netwatch header' };
  return { ok: true };
}

module.exports = { newToken, authorize, limiter, tokenOk, hostOk, originOk, peerOk };
