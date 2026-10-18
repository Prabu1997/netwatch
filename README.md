# Netwatch

A local dashboard that shows every network connection leaving your Linux machine, live:
which **process and user** opened it, **who owns the remote IP** (ASN / organisation), and whether it
is on a **public malware/C2 blocklist**. Suspicious connections are highlighted, raise an alert, and
can be **blocked with iptables**.

Zero npm dependencies (Node.js built-ins only), runs in one Docker container, everything stays on your machine.

## What it detects

| Signal | Severity |
|---|---|
| Remote IP on a threat feed (abuse.ch Feodo, Emerging Threats, Spamhaus DROP, IPsum, your own list) | HIGH |
| Shell / netcat / socat holding an external connection (possible reverse shell) | HIGH |
| Binary deleted from disk while running, or executing from `/tmp`, `/dev/shm`, `/var/tmp` | HIGH |
| Established connection with no identifiable process | MED |
| Tor exit node | MED |
| Uncommon remote port, service listening on all interfaces | LOW |

The owner (e.g. AWS) is shown but never trusted: a feed hit on an AWS IP is still flagged. Cloud providers just get a small "cloud" tag.

## Firewall mode (Linux and macOS)

Netwatch runs natively on both. Linux uses `ss` + `/proc` + iptables; macOS uses `lsof` + `ps` + `pf`.

- **App-ID**: with root, `tcpdump` feeds a parser that reads TLS SNI, JA3 hash, HTTP Host and DNS names, so each connection is labelled
  with an application (github, youtube, ssh, ...), not just a port. Without root it falls back to process and port.
- **Policy**: copy `policy.example.json` to `data/policy.json`. Rules are checked top to bottom, first match wins, and the file reloads
  while running. Fields: `action` (allow/deny/alert), `app`, `proc`, `user`, `proto`, `dst` (IP, CIDR, `feed:<id>`, `feed:any`), `dport`, `country`, `external`.
- **Enforcement** is opt-in: `ENFORCE=1` blocks destinations matched by a `deny` rule. macOS needs `sudo`; undo with `sudo pfctl -f /etc/pf.conf`.
- Not done yet: decrypting TLS, so encrypted payloads are classified by SNI and metadata only.

Run on macOS: `sudo node server.js`. Tests: `npm test`; root-only integration tests: `npm run test:integration`.

## Requirements

- Linux (uses `ss` and `/proc`)
- Docker (Engine) running, and your user able to run `docker` (`sudo usermod -aG docker $USER`, then log out/in)

## Setup and run

```bash
git clone https://github.com/<your-user>/netwatch.git
cd netwatch
./netwatch.sh start          # builds the image on first run, then starts it
./netwatch.sh open           # or browse to http://127.0.0.1:8080
```

That is all. The container uses `--restart unless-stopped`, so **it starts automatically every time the laptop boots**
(Docker itself starts at boot; check with `systemctl is-enabled docker`, enable with `sudo systemctl enable docker`).

Automatically drop traffic to malicious IPs (off by default):

```bash
AUTOBLOCK=1 ./netwatch.sh start
```

## Start, stop, manage

| Command | What it does |
|---|---|
| `./netwatch.sh start` | Start (and re-enable auto-start on boot) |
| `./netwatch.sh stop` | Stop, and do **not** start again at boot until you run `start` |
| `./netwatch.sh restart` | Stop then start |
| `./netwatch.sh status` | Running? Auto-start on? |
| `./netwatch.sh logs` | Follow the logs |
| `./netwatch.sh alerts` | Print logged malicious-IP alerts (JSON lines) |
| `./netwatch.sh unblock-all` | Remove every iptables rule Netwatch added |
| `./netwatch.sh uninstall` | Remove container, image and rules |

Change the port with `PORT=9090 ./netwatch.sh start`.

## Using the dashboard

- Rows are sorted by risk; red = HIGH, orange = MED, yellow = LOW. Closed connections stay visible, dimmed, for 5 minutes.
- A red banner lists active connections to known-malicious IPs, plus a browser notification, beep and flashing tab title (allow notifications when asked).
- Hover **threat feeds** in the header for per-feed status. Feeds download at start and refresh once they are over 24h old (checked hourly); a failed feed keeps its last good copy.
- **block / unblock** buttons add or remove an iptables `DROP` rule for that IP (`AUTOBLOCK=1` does it automatically for HIGH feed hits).
- Your own blocklist: add IPs/CIDRs, one per line, to `data/custom.txt` inside the volume:
  `docker run --rm -v netwatch-data:/d alpine sh -c 'echo 203.0.113.7 >> /d/custom.txt'`

## Security notes (read before running)

- The container runs as root with `--network host --pid host`, `SYS_PTRACE`, `NET_ADMIN` and AppArmor unconfined. That is what lets it see every socket and process and add firewall rules. Review `netwatch.sh` and `block.js` first; the code is small.
- The dashboard listens on **127.0.0.1 only**. Do not expose it: it has no login and can add firewall rules. The block API additionally requires a custom header and a localhost `Host`, so other websites cannot drive it.
- Block rules live on the **host** in a `NETWATCH` iptables/ip6tables chain and survive stopping the container. Remove them with `./netwatch.sh unblock-all`.
- Blocklists have false positives, and blocking a shared IP (CDN) cuts all sites behind it. Keep `AUTOBLOCK` off if unsure.
- Privacy: the app contacts the feed URLs once a day, and sends remote IPs to your configured DNS resolver for reverse-DNS and Team Cymru ASN lookups. No telemetry.
- Detection is heuristic and poll-based (every 2s): a connection that opens and closes between polls is missed. It is a visibility aid, not a replacement for an IDS.

## How it works

`server.js` polls `ss -tunap`, resolves each socket's process via `/proc`, and serves a Server-Sent-Events stream to
`public/index.html`. `intel.js` handles feeds, CIDR matching and ASN lookups; `block.js` manages the iptables chain.

Run without Docker (needs Node 18+ and `iproute2`): `node server.js` (run as root to see all processes).

## Data

Everything persistent is in the `netwatch-data` Docker volume: `feeds.json` (cached feeds), `alerts.jsonl`, `blocked.json`, `custom.txt`.

## License

MIT
