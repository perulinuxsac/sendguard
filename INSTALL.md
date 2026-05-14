# SendGuard Agent — Installation Guide

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Build from Source](#build-from-source)
3. [Quick Install (recommended)](#quick-install-recommended)
4. [Manual Installation](#manual-installation)
5. [Configuration Reference](#configuration-reference)
6. [Post-Install Verification](#post-install-verification)
7. [Upgrading](#upgrading)
8. [Uninstalling](#uninstalling)
9. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Operating system

| Family | Distributions | Firewall |
|---|---|---|
| RHEL | RHEL 7+, CentOS 7+, Rocky Linux 8+, AlmaLinux 8+, Fedora | `firewalld` |
| Debian | Ubuntu 20.04+, Debian 11+ | `ufw` |

### Firewall must be active before installing

```bash
# RHEL/Rocky/AlmaLinux
systemctl start firewalld && systemctl enable firewalld

# Ubuntu/Debian
ufw enable
```

### Other requirements

- Zimbra 8.8+ or 9.x/10.x installed at `/opt/zimbra`
- `systemd`
- Root access
- Go 1.22+ (build host only; not required on the Zimbra server)

---

## Build from Source

Run this on your **build host** (not necessarily the Zimbra server):

```bash
git clone https://github.com/perulinux/sendguard
cd sendguard

# Produces dist/sendguard-agent, dist/sendguard-ctl, and dist/sendguard-<version>.tar.gz
make package
```

The binaries are statically linked (`CGO_ENABLED=0`), targeting `GOOS=linux GOARCH=amd64`. Copy the tarball to the Zimbra server:

```bash
scp dist/sendguard-*.tar.gz root@your-mailserver:/tmp/
```

---

## Quick Install (recommended)

On the **Zimbra server** as root:

```bash
mkdir -p /tmp/sendguard
tar -xzf /tmp/sendguard-*.tar.gz -C /tmp/sendguard
cd /tmp/sendguard
bash install.sh
```

The installer will:

1. Detect the OS family and select the appropriate firewall backend
2. Locate Zimbra binaries and configuration directories
3. Find the active mail log (`/var/log/mail.log` or `/var/log/maillog`)
4. Prompt for configuration values interactively
5. Write `/etc/sendguard/agent.yaml`
6. Install and start the `sendguard-agent` systemd service
7. Verify that the agent is running and the API responds

### Interactive prompts

| Prompt | Example | Notes |
|---|---|---|
| Server ID | `cliente-abc-mail1` | Unique identifier for this server |
| Client name | `Laboratorios ABC` | Human-readable label |
| Allowed countries | `PE,US` | Comma-separated ISO-3166 codes for GeoIP |
| Whitelist IPs | `192.168.10.0/24` | Office networks (comma-separated CIDRs) |
| Whitelist accounts | `admin@example.com` | Accounts exempt from detection |
| Telegram bot token | `123456:ABC...` | Leave blank to skip |
| Telegram chat ID | `-1001234567890` | Leave blank to skip |
| Controller URL | `https://ctrl.example.com` | Leave blank for standalone mode |
| Controller API key | `sg-key-...` | Leave blank for standalone mode |

---

## Manual Installation

Use this if you prefer to manage configuration by hand or automate via Ansible/Chef.

### 1. Install binaries

```bash
install -m 755 dist/sendguard-agent /usr/local/bin/sendguard-agent
install -m 755 dist/sendguard-ctl   /usr/local/bin/sendguard-ctl
```

### 2. Create directories

```bash
mkdir -p /etc/sendguard /var/lib/sendguard
chmod 750 /etc/sendguard /var/lib/sendguard
```

### 3. Write configuration

Copy the example below to `/etc/sendguard/agent.yaml` and edit as needed.
See [Configuration Reference](#configuration-reference) for all options.

```bash
chmod 640 /etc/sendguard/agent.yaml
```

### 4. Install systemd service

```bash
install -m 644 deploy/sendguard-agent.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now sendguard-agent
```

---

## Configuration Reference

Full annotated `agent.yaml`:

```yaml
# Unique identifier for this server (appears in alerts and audit log)
server_id: "my-server-mail1"

# Human-readable client/organization name
client_name: "My Organization"

# ── Zimbra paths ────────────────────────────────────────────────────────────
zimbra:
  logs:
    main: "/var/log/mail.log"          # RHEL: /var/log/maillog
    mailbox: "/opt/zimbra/log/mailbox.log"  # optional; omit or leave blank to disable
  workers: 4
  postfix_sbin: "/opt/zimbra/common/sbin"  # or /opt/zimbra/postfix/sbin
  postfix_conf: "/opt/zimbra/common/conf"  # or /opt/zimbra/postfix/conf

# ── Detection rules ─────────────────────────────────────────────────────────
rules:
  auth_failed:
    max_auth_failures: 5    # block IP after N SASL failures
    scan_time: 300          # sliding window in seconds

  number_messages:
    max_messages: 300       # suspend account after N messages sent
    scan_time: 3600

  sasl_connections:
    max_sasl_connections: 20  # block IP after N concurrent SASL connections
    scan_time: 300

  impossible_traveler:
    window_minutes: 30      # minimum travel time between two login locations

  queue_monitor:
    queue_threshold: 2500   # purge queue when domain has N deferred messages
    scan_time: 3600

  domain_discovery:
    max_domains: 10         # block IP connecting to N distinct destination domains
    scan_time: 600

  bounce_rate:
    max_bounces: 50         # suspend account after N bounces
    scan_time: 300

# ── GeoIP ────────────────────────────────────────────────────────────────────
geoip:
  api_url: "https://ipinfo.io/lite"
  cache_ttl: 24             # hours to cache GeoIP responses
  allowed_countries:
    - "PE"
    - "US"

# ── AbuseIPDB (optional) ─────────────────────────────────────────────────────
abuseipdb:
  api_key: ""               # leave blank to disable
  cache_ttl: 24             # hours

# ── Firewall ─────────────────────────────────────────────────────────────────
firewall:
  backend: "firewalld"      # "firewalld" (RHEL) or "ufw" (Ubuntu/Debian)
  ban_seconds: 3600         # 0 = permanent ban

# ── Local SQLite database ────────────────────────────────────────────────────
local_db:
  path: "/var/lib/sendguard/sendguard.db"
  max_size_mb: 100

# ── Controller (optional) ────────────────────────────────────────────────────
# Leave url blank for standalone mode; alerts are stored locally only.
controller:
  url: ""
  api_key: ""
  sync_interval: 30         # seconds between sync attempts
  batch_size: 100           # alerts per HTTP POST

# ── Audit log (optional) ─────────────────────────────────────────────────────
audit_log:
  path: "/var/log/sendguard-audit.log"  # NDJSON; leave blank to disable

# ── HTTP API ─────────────────────────────────────────────────────────────────
api:
  listen: "127.0.0.1:9099"  # leave blank to disable the API
  api_key: ""               # if set, write endpoints require X-Api-Key header

# ── Notifications ─────────────────────────────────────────────────────────────
notification:
  telegram:
    token: ""               # bot token; leave blank to disable
    chat_id: ""             # chat/group/channel ID
  webhook:
    url: ""                 # HTTP endpoint (Slack, Teams, n8n, etc.); blank to disable
    timeout: 10             # seconds

# ── Whitelist ─────────────────────────────────────────────────────────────────
# Entries here are never blocked or suspended regardless of detection results.
whitelist:
  ips:
    - "192.168.10.0/24"     # office network
  accounts:
    - "admin@example.com"
```

---

## Post-Install Verification

```bash
# Check service is running
systemctl status sendguard-agent

# Follow live logs
journalctl -u sendguard-agent -f

# Query the API
sendguard-ctl status
sendguard-ctl health

# Check Prometheus metrics
curl -s http://127.0.0.1:9099/metrics

# View current whitelist
sendguard-ctl whitelist list

# Test IP intelligence (requires GeoIP and/or AbuseIPDB configured)
sendguard-ctl urban 1.2.3.4
```

### Expected initial output of `sendguard-ctl status`

```
SendGuard  version: v0.1.0  uptime: 5s

Counters:
  events processed : 0
  alerts emitted   : 0
  IPs blocked      : 0
  accounts suspended: 0
  rate-limits      : 0

No IPs currently blocked.
```

---

## Upgrading

```bash
# Stop the service
systemctl stop sendguard-agent

# Replace the binaries
install -m 755 dist/sendguard-agent /usr/local/bin/sendguard-agent
install -m 755 dist/sendguard-ctl   /usr/local/bin/sendguard-ctl

# Restart
systemctl start sendguard-agent
systemctl status sendguard-agent
```

Configuration and the SQLite database at `/var/lib/sendguard/sendguard.db` are preserved across upgrades. Active bans are restored from the database on startup.

---

## Uninstalling

```bash
systemctl stop sendguard-agent
systemctl disable sendguard-agent
rm -f /etc/systemd/system/sendguard-agent.service
systemctl daemon-reload

rm -f /usr/local/bin/sendguard-agent /usr/local/bin/sendguard-ctl
rm -rf /etc/sendguard /var/lib/sendguard
# Optionally: rm -f /var/log/sendguard-audit.log
```

---

## Troubleshooting

### Service fails to start

```bash
journalctl -u sendguard-agent -n 50 --no-pager
```

Common causes:

| Error message | Fix |
|---|---|
| `no se pudo cargar la configuración` | Check YAML syntax: `python3 -c "import yaml,sys; yaml.safe_load(sys.stdin)" < /etc/sendguard/agent.yaml` |
| `zimbra.logs.main es obligatorio` | Set `zimbra.logs.main` to the correct mail log path |
| `no se pudo abrir base de datos local` | Ensure `/var/lib/sendguard` exists and is writable by root |
| `no se pudo abrir audit log` | Ensure the parent directory of `audit_log.path` is writable |

### Agent starts but no blocks are happening

1. Confirm the correct mail log is configured (`zimbra.logs.main`). Check it is actively receiving new lines: `tail -f /var/log/mail.log`
2. Check that the firewall backend matches the OS: `firewall.backend: "ufw"` on Ubuntu, `"firewalld"` on RHEL.
3. Lower the detection thresholds temporarily and watch `journalctl -u sendguard-agent -f` for `enforcement: IP bloqueada` or `enforcement: cuenta suspendida` messages.
4. Verify the whitelist is not covering the test IP: `sendguard-ctl whitelist list`

### firewalld: rules are not being added

```bash
systemctl is-active firewalld
firewall-cmd --state
# Verify the agent can call firewall-cmd
firewall-cmd --list-rich-rules
```

### ufw: rules are not being added

```bash
ufw status
# The service needs /etc/ufw to be writable (ReadWritePaths in the service unit)
grep ReadWritePaths /etc/systemd/system/sendguard-agent.service
# Should include /etc/ufw
```

### Telegram notifications not arriving

1. Confirm `notification.telegram.token` and `chat_id` are set.
2. Test the bot token manually:
   ```bash
   curl -s "https://api.telegram.org/bot<TOKEN>/getMe"
   ```
3. Make sure the bot has been added to the target chat and has permission to post.

### API returns 401

Pass the API key with `-key`:
```bash
sendguard-ctl -addr http://127.0.0.1:9099 -key your-api-key block 1.2.3.4
```

Or via `curl`:
```bash
curl -H "X-Api-Key: your-api-key" -X POST http://127.0.0.1:9099/blocked/1.2.3.4
```

### Bans not surviving restarts

Ensure `local_db.path` points to a writable location. On first start, SendGuard creates the SQLite file automatically. Check:
```bash
ls -lh /var/lib/sendguard/sendguard.db
```
