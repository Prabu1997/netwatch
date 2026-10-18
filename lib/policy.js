// Security policy: an ordered rule list, first match wins, like a Palo Alto security rulebase. Pure functions.
// Rule: { name, action: 'allow'|'deny'|'alert', proto?, app?: [..], proc?: [..], user?: [..],
//         dst?: [ip|cidr|'feed:<id>'|'feed:any'], dport?: [n|'a-b'], country?: [cc], external?: bool }
// Omitted fields match anything. Unknown actions are rejected by validate().
const net = require('net');

const ACTIONS = new Set(['allow', 'deny', 'alert']);
const FIELDS = new Set(['name', 'action', 'proto', 'app', 'proc', 'user', 'dst', 'dport', 'country', 'external', 'disabled', 'domain']);

const { valid: validDomain, norm: normDomain } = require('./domains');

// "evil.com" matches evil.com and any subdomain, never "notevil.com".
const domainMatch = (name, pattern) => { const n = normDomain(name), p = normDomain(pattern); return !!n && (n === p || n.endsWith('.' + p)); };

const toInt = ip => ip.split('.').reduce((a, o) => a * 256 + +o, 0);

function inCidr(ip, cidr) {
  if (!cidr.includes('/')) return ip === cidr;
  const [base, bitsStr] = cidr.split('/'), bits = +bitsStr;
  if (net.isIPv4(ip) && net.isIPv4(base) && bits >= 0 && bits <= 32)
    return bits === 0 || ((toInt(ip) ^ toInt(base)) >>> (32 - bits)) === 0;
  return false; // IPv6 CIDRs are not supported yet: only exact v6 addresses match
}

function portMatch(port, spec) {
  if (typeof spec === 'number') return port === spec;
  const m = String(spec).match(/^(\d+)(?:-(\d+))?$/);
  if (!m) return false;
  return port >= +m[1] && port <= +(m[2] || m[1]);
}

const anyOf = (list, test) => !list || list.some(test);

function matches(rule, ctx) {
  if (rule.disabled) return false;
  if (rule.proto && rule.proto !== ctx.proto) return false;
  if (rule.external != null && rule.external !== !!ctx.external) return false;
  if (!anyOf(rule.app, a => a === ctx.app)) return false;
  if (!anyOf(rule.proc, p => p === ctx.proc)) return false;
  if (!anyOf(rule.user, u => u === ctx.user)) return false;
  if (!anyOf(rule.country, c => c === ctx.cc)) return false;
  if (rule.domain && !rule.domain.some(d => domainMatch(ctx.domain, d))) return false; // a domain rule never matches a flow with no known name
  if (!anyOf(rule.dport, p => portMatch(ctx.rport, p))) return false;
  if (!anyOf(rule.dst, d => (d.startsWith('feed:')
    ? (d === 'feed:any' ? (ctx.feeds || []).length > 0 : (ctx.feeds || []).includes(d.slice(5)))
    : inCidr(ctx.rip, d)))) return false;
  return true;
}

// Returns { action, rule, index }. With no match the default applies (allow: this is a monitor first).
function evaluate(rules, ctx, defaultAction = 'allow') {
  for (let i = 0; i < rules.length; i++) if (matches(rules[i], ctx)) return { action: rules[i].action, rule: rules[i].name, index: i };
  return { action: defaultAction, rule: 'default', index: -1 };
}

function validate(rules) {
  const errs = [];
  if (!Array.isArray(rules)) return ['rules must be an array'];
  rules.forEach((r, i) => {
    const at = `rule ${i + 1}${r && r.name ? ` (${r.name})` : ''}`;
    if (!r || typeof r !== 'object') return errs.push(`${at}: not an object`);
    if (!r.name) errs.push(`${at}: missing name`);
    if (!ACTIONS.has(r.action)) errs.push(`${at}: action must be allow, deny or alert`);
    for (const k of Object.keys(r)) if (!FIELDS.has(k)) errs.push(`${at}: unknown field "${k}"`);
    for (const d of Array.isArray(r.domain) ? r.domain : []) if (!validDomain(d)) errs.push(`${at}: bad domain "${d}" (need a name like example.com; single labels such as "com" are refused)`);
    for (const k of ['app', 'proc', 'user', 'dst', 'dport', 'country', 'domain'])
      if (r[k] != null && !Array.isArray(r[k])) errs.push(`${at}: ${k} must be an array`);
    for (const d of r.dst || []) {
      if (d.startsWith('feed:')) continue;
      const [ip, bits] = String(d).split('/');
      if (!net.isIP(ip) || (bits != null && !(+bits >= 0 && +bits <= (net.isIPv6(ip) ? 128 : 32)))) errs.push(`${at}: bad dst "${d}"`);
    }
    for (const p of r.dport || []) if (!/^\d+(-\d+)?$/.test(String(p))) errs.push(`${at}: bad dport "${p}"`);
  });
  return errs;
}

module.exports = { evaluate, matches, validate, inCidr, domainMatch };
