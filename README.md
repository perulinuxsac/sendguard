# SendGuard Agent

SendGuard Agent is a lightweight security daemon for Zimbra mail servers. It tails the mail logs in real time, detects suspicious patterns using configurable detection modules, and automatically enforces containment actions — IP blocks via `firewalld` or `ufw`, account suspensions via `zmprov`, and Postfix queue management.

---

## Features

- **Real-time log analysis** — tail-follows `mail.log` and `mailbox.log` without polling delays
- **11 detection modules** — each tuned with configurable thresholds and time windows
- **Multi-OS firewall support** — `firewalld` (RHEL/CentOS/Rocky/AlmaLinux) and `ufw` (Ubuntu/Debian)
- **Account suspension** — locks compromised Zimbra accounts via `zmprov`
- **Postfix rate-limiting and queue purging** — throttles sending or deletes queued spam per domain
- **Postfix policy daemon** — `sendguard-policyd` rejects connections from blocked IPs at SMTP time via `check_policy_service`
- **GeoIP intelligence** — restricts logins to allowed countries via [ipinfo.io](https://ipinfo.io)
- **AbuseIPDB enrichment** — annotates blocks with reputation scores
- **Telegram, webhook and email notifications** — instant alerts on block/suspend actions
- **Notification throttling** — per-IP/account cooldown and global rate cap to prevent alert floods
- **REST API** — observe state and issue manual commands without touching the server
- **SQLite persistence** — bans survive agent restarts
- **StoreAndForward** — queues alerts locally when the central Controller is unreachable
- **Audit log** — append-only NDJSON record of every enforcement action

---

## Detection Modules

### Quick reference

| Module | Score | Data source | Action |
|---|:-:|---|---|
| `auth_failed` | 60 | SASL failures in `mail.log` | Block IP |
| `number_messages` | 80 | `qmgr` events in `mail.log` | Suspend account |
| `sasl_connections` | 65 / 90 | SASL successes in `mail.log` | Suspend account / Block IP + Suspend account |
| `dist_brute_force` | 55 | SASL failures in `mail.log` | Notify only |
| `impossible_traveler` | 85 | Auth successes + GeoIP | Suspend account |
| `queue_monitor` | 70 | Deferred messages in `mail.log` | Notify admin |
| `domain_discovery` | 75 | SASL failures in `mail.log` | Block IP |
| `bounce_rate` | 85 | Bounce events in `mail.log` | Suspend account |
| `rcpt_flood` | 90 | RCPT filter lines in `mail.log` | Block IP + Suspend account |
| `password_spray` | 85 | SASL failures in `mail.log` | Block IP |
| `account_takeover` | 80 / 95 | Auth failures + successes + `qmgr` | Suspend account / Block IP + Suspend account |

---

### Module details

#### `auth_failed` — Classic brute-force by IP

Maintains a sliding window of SASL failure timestamps per IP. On every failure the module discards events older than `scan_time` and appends the new one. When the IP reaches `max_auth_failures` within the window, it emits a block and resets the counter so future attempts accumulate from zero.

- **Score:** 60 &nbsp;|&nbsp; **Action:** Block IP
- **Defaults:** 5 failures / 5 minutes
- Does **not** suspend any account — the module only knows the attacking IP, not whose credentials are being tried.

---

#### `number_messages` — Anomalous outbound volume

Reads every `qmgr` `from=<account>` event (the earliest point at which Postfix knows the authenticated sender and has accepted the message for delivery). Accumulates message timestamps per account. When an account exceeds `max_messages` in the window, it is suspended. Empty-sender messages (`from=<>`, NDRs/bounces) are ignored to prevent false positives.

- **Score:** 80 &nbsp;|&nbsp; **Action:** Suspend account
- **Defaults:** 300 messages / 1 hour
- Does **not** block the source IP — legitimate senders may connect from Outlook Mobile or other app proxies.

---

#### `sasl_connections` — Botnet reusing a compromised account (two variants)

Accumulates every authenticated SASL connection for each account, recording IP and timestamp.

**Variant A — Distributed botnet (score 90):** N distinct IPs authenticated as the same account → the credentials were distributed across a botnet. Double action: **suspend account + block every unique IP** seen in the window.

**Variant B — Concentrated botnet (score 65):** too many total SASL connections from the same account (even from few IPs) → intensive single-node or small-group attack. Action: **suspend account only**.

- **Defaults:** 5 unique IPs or 20 total connections / 5 minutes

---

#### `dist_brute_force` — Distributed credential stuffing

The inverse of `password_spray`. Multiple distinct IPs each fail once or twice against the **same account** — enough to stay below `auth_failed`'s per-IP threshold. The module counts unique failing IPs per account. On reaching `max_ips` it does **not** block or suspend (false-positive risk is high when each IP does very little), but **notifies the admin** for manual investigation.

- **Score:** 55 &nbsp;|&nbsp; **Action:** Notify only
- **Defaults:** 5 distinct IPs / 5 minutes

---

#### `impossible_traveler` — Logins from geographically impossible locations

Stores the last known login for each account (country, IP, timestamp). When a new successful login arrives, it compares the new country against the previous one. If they differ and the elapsed time is shorter than `window_minutes`, a physical journey between them is impossible → the account is compromised.

Known mail-client proxies (Outlook Mobile, Gmail, iCloud, etc.) are fully skipped — neither recorded nor compared. If both countries are in `allowed_countries`, no alert is raised. If GeoIP cannot resolve the IP, the event is silently ignored (avoids false positives).

- **Score:** 85 &nbsp;|&nbsp; **Action:** Suspend account
- **Defaults:** 30-minute window
- Does **not** block the IP — it may be legitimate in its own country.
- Requires GeoIP (local MMDB or HTTP API fallback).

---

#### `queue_monitor` — Destination domain rejecting messages

Groups deferred Postfix messages (`status=deferred`) by destination domain extracted from `to=<user@domain>`. When a domain accumulates more than `queue_threshold` deferrals in the window, the server's IP is likely on an RBL or has a reputation problem with that destination. The module notifies the admin so they can investigate and decide whether to intervene manually.

- **Score:** 70 &nbsp;|&nbsp; **Action:** Notify admin only
- **Defaults:** 2 500 deferrals / 1 hour
- Does **not** purge, block, or suspend — deferred messages are retried automatically by Postfix; purging would cause permanent loss of legitimate emails. The admin decides whether to intervene manually.

---

#### `domain_discovery` — Multi-organisation credential spray

Detects the pattern where a single IP probes accounts across **many different organisations** — a low density of failures per domain, high diversity of target domains. This is the hallmark of botnets operating from purchased or leaked email lists. The module counts distinct domains of failed login attempts per IP using a tumbling window (when the window expires it resets completely). On reaching `max_domains`, the IP is blocked.

- **Score:** 75 &nbsp;|&nbsp; **Action:** Block IP
- **Defaults:** 10 distinct domains / 10 minutes

---

#### `bounce_rate` — Account generating mass bounces

A spike of Non-Delivery Reports (NDRs) in a short window is a clear sign of a compromised account sending spam to harvested or invalid address lists. The module correlates `status=bounced` delivery events back to the authenticated sender (via the `queueSenders` map built from `qmgr` events) and counts bounces per account. On exceeding `max_bounces`, the account is suspended.

- **Score:** 85 &nbsp;|&nbsp; **Action:** Suspend account
- **Defaults:** 50 bounces / 5 minutes
- Does **not** block the source IP — the sender may be using webmail or a mobile app.

---

#### `rcpt_flood` — Mass-recipient spam from an authenticated session

Counts RCPT TO additions per authenticated IP from Postfix `filter: RCPT from` lines (authenticated sessions only — inbound MX deliveries are ignored). A legitimate mail client adds 1–5 recipients; a compromised account sending spam can add hundreds per second. On exceeding `max_recipients`, two alerts are emitted: **block the IP** and **suspend the authenticated sender account**.

- **Score:** 90 &nbsp;|&nbsp; **Action:** Block IP + Suspend account
- **Defaults:** 50 recipients / 5 minutes

---

#### `password_spray` — Single IP probing many accounts

The complement of `dist_brute_force`. One IP fails against **many distinct accounts** with few attempts each — the classic "password spraying" technique (e.g. trying `Enero2024!` against every known email) that stays below per-account lockout thresholds. The module accumulates unique failing accounts per IP. On reaching `max_accounts`, the IP is blocked.

- **Score:** 85 &nbsp;|&nbsp; **Action:** Block IP
- **Defaults:** 10 distinct accounts / 5 minutes
- Does **not** suspend any account — the victim accounts successfully resisted the attack.

---

#### `account_takeover` — Brute-force that succeeded

The most sophisticated module. It watches for the worst-case outcome of a brute-force attack: the attacker eventually finds the correct password. It tracks auth failures per account and correlates them against subsequent successes or outbound messages.

**Pattern A (score 95):** the same IP that accumulated N failures gets a successful login → password found by brute-force. Very high confidence. **Suspend account + block that IP.**

**Pattern B (score 80):** the account accumulated N failures from various IPs and shortly after sends a message (even from a different IP — e.g. via webmail). High confidence of takeover. **Suspend account** and block the IP with the most prior attempts.

- **Defaults:** 5 minimum failures / 10-minute correlation window

---

### Score and action reference

| Score | Confidence | Action | Module(s) |
|:-:|---|---|---|
| 55 | Suspicious, investigate | Notify only | `dist_brute_force` |
| 60 | Brute-force confirmed | Block IP | `auth_failed` |
| 65 | Botnet reusing account | Suspend account | `sasl_connections` (concentrated) |
| 70 | Server reputation problem | Notify admin | `queue_monitor` |
| 75 | Multi-org scan | Block IP | `domain_discovery` |
| 80 | Mass spam / account taken | Suspend account | `number_messages`, `account_takeover` (B) |
| 85 | High-confidence compromise | Suspend account **or** Block IP¹ | `impossible_traveler`, `bounce_rate`, `password_spray` |
| 90 | Near-certain compromise | Block IP + Suspend account | `sasl_connections` (distributed), `rcpt_flood` |
| 95 | Certainty: password found | Block IP + Suspend account | `account_takeover` (A) |

> ¹ At score 85: `impossible_traveler` and `bounce_rate` suspend the account without blocking the IP; `password_spray` blocks the IP without suspending any account.

---

## Architecture

```
mail.log ──┐
           ├── watcher ──► parser ──► eventCh ──► engine ──► alertCh ──► enforcer
mailbox.log ┘                                    (modules)              │
                                                                        ├── firewall (block IP)
                                                                        ├── zmprov  (suspend account)
                                                                        ├── postfix (rate-limit)
                                                                        ├── notifier (Telegram / webhook)
                                                                        ├── audit log (NDJSON)
                                                                        └── forwarder ──► Controller
```

The pipeline is fully asynchronous. Each watcher goroutine writes events to a buffered channel (capacity 10 000); the engine distributes them to all enabled modules. Modules emit `Alert` structs into a second channel (capacity 1 000) consumed by the enforcer.

---

## REST API

The agent exposes an HTTP API on `127.0.0.1:9099` (configurable). Protected endpoints require `X-Api-Key` when `api.api_key` is set.

### Read-only endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Liveness check |
| `GET` | `/status` | Blocked IPs, enforcement counters, uptime |
| `GET` | `/metrics` | Prometheus text format |
| `GET` | `/urban/{ip}` | IP intelligence: GeoIP + AbuseIPDB |
| `GET` | `/queue` | Current Postfix mail queue |
| `GET` | `/domains` | Domains with accumulated alerts |
| `GET` | `/whitelist` | Current whitelist contents |
| `GET` | `/blocked/{ip}` | O(1) check whether an IP is currently blocked (used by `sendguard-policyd`) |

### Protected endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/blocked/{ip}` | Manually block an IP |
| `DELETE` | `/blocked/{ip}` | Manually unblock an IP |
| `DELETE` | `/suspended/{account}` | Unsuspend a Zimbra account |
| `POST` | `/whitelist/{value}` | Add IP/CIDR or account to whitelist |
| `DELETE` | `/whitelist/{value}` | Remove IP/CIDR or account from whitelist |

---

## sendguard-ctl

`sendguard-ctl` is the command-line client for the API:

```
sendguard-ctl [-addr http://127.0.0.1:9099] [-key <api-key>] <command>

Commands:
  status                      show blocked IPs and counters
  block   <ip>                manually block an IP
  unblock <ip>                manually unblock an IP
  unsuspend <account>         unsuspend a Zimbra account
  health                      verify the agent is alive
  urban   <ip>                IP intelligence (AbuseIPDB + GeoIP)
  queue                       current Postfix mail queue
  domains                     domains with accumulated alerts
  whitelist list              show current whitelist
  whitelist add    <val>      add IP/CIDR or account (in-memory)
  whitelist remove <val>      remove IP/CIDR or account (in-memory)
```

> **Note:** `whitelist add/remove` changes are in-memory only. Edit `agent.yaml` to make them persistent across restarts.

---

## Requirements

- Linux (RHEL 7+/CentOS/Rocky/AlmaLinux or Ubuntu 20.04+/Debian 11+)
- Zimbra 8.8+ or 9.x/10.x installed at `/opt/zimbra`
- `firewalld` (RHEL family) or `ufw` (Debian family) installed and active
- Root privileges (for firewall and `zmprov` commands)
- Go 1.22+ (to build from source)

---

## Quick Start

```bash
# 1. Build the binaries
make package

# 2. Copy the release tarball to the Zimbra server and extract
scp dist/sendguard-*.tar.gz root@mailserver:/tmp/
ssh root@mailserver "mkdir -p /tmp/sendguard && tar -xzf /tmp/sendguard-*.tar.gz -C /tmp/sendguard"

# 3. Run the interactive installer
cd /tmp/sendguard
bash install.sh
```

The installer auto-detects the OS, firewall backend, Zimbra paths, and mail log location. It will prompt for:
- Server ID and client name
- Allowed countries (GeoIP)
- Office network CIDRs and account whitelist
- Telegram bot token and chat ID (optional)
- Central Controller URL and API key (optional; leave blank for standalone mode)
- Email notifications — from/to addresses for alerts and daily report (optional)
- AbuseIPDB API key for reputation enrichment (optional; free at abuseipdb.com)
- MaxMind account ID and license key for local GeoIP database (optional; free at maxmind.com)

See [INSTALL.md](INSTALL.md) for full installation details and configuration reference.

---

## Building from Source

```bash
# Clone and build
git clone https://github.com/perulinux/sendguard
cd sendguard
make build build-ctl build-policyd  # produces dist/sendguard-agent, dist/sendguard-ctl, dist/sendguard-policyd
make package             # creates dist/sendguard-<version>.tar.gz with service + install.sh
make test                # run test suite
make lint                # run golangci-lint
```

---

## License

See [LICENSE](LICENSE).
