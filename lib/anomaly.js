// Behavioral detections that need no threat feed: a fresh attacker server on a clean IP still trips these. Pure functions.

// Protocol seen on the wire vs. the port it uses. Attackers hide C2 on 443/80/53 because those ports are rarely blocked.
// Mail/FTP/XMPP ports are excluded for TLS because STARTTLS legitimately sends a ClientHello mid-stream.
const WEB_DNS_PORTS = new Set([53, 80, 443, 8080, 8443]);
const TLS_PORTS_WRONG = new Set([22, 53, 80, 123]);
const TLS_PORTS_OK = new Set([443, 8443]);

function protocolMismatch(flow, { rport, proto }) {
  const out = [];
  if (!flow || !flow.l7 || proto === 'udp') return out;
  if (flow.l7 === 'ssh' && WEB_DNS_PORTS.has(rport))
    out.push(['med', `SSH traffic on port ${rport}: a web/DNS port used to hide a remote shell or tunnel`, 'anomaly']);
  if (flow.l7 === 'http' && TLS_PORTS_OK.has(rport))
    out.push(['med', `Plain HTTP on TLS port ${rport}: expected encrypted traffic`, 'anomaly']);
  if (flow.l7 === 'tls' && TLS_PORTS_WRONG.has(rport))
    out.push(['med', `TLS traffic on port ${rport}: expected ${rport === 22 ? 'SSH' : rport === 80 ? 'HTTP' : 'plain protocol'}`, 'anomaly']);
  return out;
}

// Processes that normally have no business making a *new* outbound friend: interpreters, shells, download tools.
// Browsers and apps are deliberately absent: they contact new sites all day and would drown the signal.
const RISKY = /^(python|python2|python3|node|perl|ruby|php|bash|sh|zsh|dash|ksh|fish|nc|ncat|netcat|socat|telnet|curl|wget|powershell|pwsh|osascript|java|lua|tclsh|awk)[\d.]*$/;
const normProc = name => String(name || '').split('/').pop().toLowerCase().replace(/\.exe$/, '');
const isRisky = name => RISKY.test(normProc(name));

module.exports = { protocolMismatch, isRisky, normProc };
