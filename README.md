# SendGuard Agent

SendGuard Agent is a lightweight security daemon for Zimbra mail servers. It tails the mail logs in real time, detects suspicious patterns using configurable detection modules, and automatically enforces containment actions — IP blocks via `firewalld` or `ufw`, account suspensions via `zmprov`, and Postfix queue management.

---

## Features

- **Real-time log analysis** — tail-follows `mail.log` and `mailbox.log` without polling delays
- **7 detection modules** — each tuned with configurable thresholds and time windows
- **Multi-OS firewall support** — `firewalld` (RHEL/CentOS/Rocky/AlmaLinux) and `ufw` (Ubuntu/Debian)
- **Account suspension** — locks compromised Zimbra accounts via `zmprov`
- **Postfix rate-limiting and queue purging** — throttles sending or deletes queued spam per domain
- **GeoIP intelligence** — restricts logins to allowed countries via [ipinfo.io](https://ipinfo.io)
- **AbuseIPDB enrichment** — annotates blocks with reputation scores
- **Telegram and webhook notifications** — instant alerts on block/suspend actions
- **REST API** — observe state and issue manual commands without touching the server
- **SQLite persistence** — bans survive agent restarts
- **StoreAndForward** — queues alerts locally when the central Controller is unreachable
- **Audit log** — append-only NDJSON record of every enforcement action

---

## Detection Modules

| Module | Trigger | Default action |
|---|---|---|
| `auth_failed` | N SASL authentication failures in a time window | Block IP |
| `number_messages` | Account sends more than N messages in a window | Suspend account |
| `sasl_connections` | IP opens more than N concurrent SASL connections | Block IP |
| `impossible_traveler` | Same account logs in from two geographically impossible locations within W minutes | Suspend account |
| `queue_monitor` | Domain has more than N deferred messages in a window | Purge queue |
| `domain_discovery` | IP connects to N distinct destination domains in a window | Block IP |
| `bounce_rate` | Account generates more than N bounces in a window | Suspend account |

---

## Architecture

```
mail.log ──┐
           ├── watcher ──► parser ──► eventCh ──► engine ──► alertCh ──► enforcer
mailbox.log ┘                                    (modules)              │
                                                                        ├── firewall (block IP)
                                                                        ├── zmprov  (suspend account)
                                                                        ├── postfix (rate-limit / purge)
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

### Protected endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/blocked/{ip}` | Manually block an IP |
| `DELETE` | `/blocked/{ip}` | Manually unblock an IP |
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
- Office network CIDRs for the whitelist
- Telegram bot token and chat ID (optional)
- Central Controller URL and API key (optional; leave blank for standalone mode)

See [INSTALL.md](INSTALL.md) for full installation details and configuration reference.

---

## Building from Source

```bash
# Clone and build
git clone https://github.com/perulinux/sendguard
cd sendguard
make build build-ctl     # produces dist/sendguard-agent and dist/sendguard-ctl
make package             # creates dist/sendguard-<version>.tar.gz with service + install.sh
make test                # run test suite
make lint                # run golangci-lint
```

---

## License

See [LICENSE](LICENSE).
