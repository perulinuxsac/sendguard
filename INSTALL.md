# SendGuard Agent — Installation Guide

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Build from Source](#build-from-source)
3. [Package Install (.deb / .rpm)](#package-install-deb--rpm)
4. [Quick Install (recommended)](#quick-install-recommended)
5. [Manual Installation](#manual-installation)
6. [Configuration Reference](#configuration-reference)
7. [Post-Install Verification](#post-install-verification)
8. [Upgrading](#upgrading)
9. [Uninstalling](#uninstalling)
10. [Troubleshooting](#troubleshooting)

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
git clone https://github.com/perulinuxsac/sendguard
cd sendguard

# Produces dist/sendguard-agent, dist/sendguard-ctl, and dist/sendguard-<version>.tar.gz
make package
```

The binaries are statically linked (`CGO_ENABLED=0`), targeting `GOOS=linux GOARCH=amd64`. Copy the tarball to the Zimbra server:

```bash
scp dist/sendguard-*.tar.gz root@your-mailserver:/tmp/
```

To build native OS packages instead of the tarball, see [Package Install (.deb / .rpm)](#package-install-deb--rpm).

---

## Package Install (.deb / .rpm)

For fleets it is cleaner to ship a native `.deb` (Debian/Ubuntu) or `.rpm`
(RHEL/Rocky/AlmaLinux) than the tarball + `install.sh`. The package installs the
software (binaries, systemd units, directories); the **per-client configuration**
(`/etc/sendguard/agent.yaml`) is still produced by Ansible or `install.sh` — the
package ships only `agent.yaml.example` and never overwrites an existing config.

### Build the packages

On the **build host** (requires Go 1.22+ and [`nfpm`](https://nfpm.goreleaser.com/)):

```bash
# Install nfpm once (single binary, no rpmbuild/dpkg toolchain needed)
go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest
export PATH="$PATH:$(go env GOPATH)/bin"

# Build from a clean release tag so the version has no -dirty/-gNNN suffix
git checkout v1.2.0
make packages         # → both .deb and .rpm
# or individually: make deb / make rpm
# or override the version: make packages VERSION=1.2.0
```

Output in `dist/`:

```
sendguard_1.2.0_amd64.deb
sendguard-1.2.0-1.x86_64.rpm
```

### What the package contains

| Path | Mode | Notes |
|---|---|---|
| `/usr/local/bin/sendguard-{agent,ctl}` | 0755 | static binaries |
| `/usr/local/lib/sendguard/remove_smtp_hooks.sh` | 0755 | removes pre-1.1.0 Postfix hooks (also the package pre-install) |
| `/etc/systemd/system/sendguard-agent.service` | 0644 | systemd unit |
| `/etc/sendguard/` | 0750 | config dir |
| `/etc/sendguard/agent.yaml.example` | 0640 | reference config (not the active one) |
| `/var/lib/sendguard/` | 0750 | SQLite DB dir |

The maintainer scripts run `systemctl daemon-reload`, enable the service, and:

- **Fresh install** — the service is enabled but **not started** (no config yet).
  The post-install prints the next steps.
- **Upgrade** — if `/etc/sendguard/agent.yaml` already exists, the agent is
  restarted with the new binaries. Upgrading from < 1.1.0: the **pre-install**
  removes the SendGuard hooks from Postfix (`check_policy_service
  inet:…:9100`, `sendguard_access`), verifies them gone, and only then stops
  and removes `sendguard-policyd` — before any file is replaced. If it cannot
  (Postfix config unreadable, hook in a `master.cf` override…), the package
  manager aborts the upgrade and the previous version stays fully intact.
- **Removal** — the service is stopped and disabled only on a real uninstall
  (not during an upgrade). `/etc/sendguard` and `/var/lib/sendguard` (config and
  database) are **preserved**.

### Install on the Zimbra server

```bash
# Debian / Ubuntu
apt install ./sendguard_1.2.0_amd64.deb

# RHEL / Rocky / AlmaLinux
dnf install ./sendguard-1.2.0-1.x86_64.rpm

# Then configure and start:
cp /etc/sendguard/agent.yaml.example /etc/sendguard/agent.yaml   # or deploy via Ansible
$EDITOR /etc/sendguard/agent.yaml                                # set server_id, client_name, ...
systemctl enable --now sendguard-agent
```

Upgrading later is just `apt install ./sendguard_<newver>_amd64.deb` /
`dnf upgrade ./sendguard-<newver>.x86_64.rpm`; the existing config and database
are kept and the agent restarts automatically.

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

1. Detect the OS family and select the firewall backend: `ufw` on Debian/Ubuntu,
   `firewalld-ipset` on RHEL (on upgrades the backend already configured is kept)
2. Locate Zimbra binaries and configuration directories
3. Find the active mail log (`/var/log/mail.log` or `/var/log/maillog`)
4. Remove the Postfix hooks left by versions < 1.1.0, if any (`remove_smtp_hooks.sh`),
   before touching any binary — if that fails, nothing is installed
5. Install the binaries and prompt for configuration values interactively
6. Download the MaxMind GeoLite2 database and install a weekly update cron (if credentials were given)
7. Write `/etc/sendguard/agent.yaml` and generate a random API key (`/etc/sendguard/api.key`)
8. Install and start the `sendguard-agent` systemd service
9. Verify that the agent is running and the API responds

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
| Email from | `sendguard@midominio.com` | Leave blank to disable email notifications |
| Email to | `noc@midominio.com` | Comma-separated recipients |
| AbuseIPDB API key | `abc123...` | Leave blank to disable (free at abuseipdb.com) |
| MaxMind Account ID | `123456` | Leave blank to use HTTP API fallback |
| MaxMind License Key | `AbCdEf...` | Required if Account ID is provided |

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

Full annotated `agent.yaml`. Every key is optional unless marked otherwise; the
values shown are the defaults. The repository's [`agent.yaml`](agent.yaml) is a
ready-to-edit example.

```yaml
# Unique identifier for this server (appears in alerts and audit log)
server_id: "my-server-mail1"

# Human-readable client/organization name
client_name: "My Organization"

# ── Zimbra ──────────────────────────────────────────────────────────────────
zimbra:
  logs:
    main: "/var/log/mail.log"               # REQUIRED. RHEL: /var/log/maillog
    mailbox: "/opt/zimbra/log/mailbox.log"  # IMAP/POP3/SOAP logins; "" disables it
  zmprov_bin: "/opt/zimbra/bin/zmprov"      # full path (systemd's PATH lacks /opt/zimbra/bin)
  # Read-only: used only to list the queue (GET /queue, sendguard-ctl queue).
  # SendGuard never modifies the SMTP configuration nor the queue.
  postfix_sbin: "/opt/zimbra/common/sbin"   # or /opt/zimbra/postfix/sbin
  postfix_conf: "/opt/zimbra/common/conf"   # or /opt/zimbra/postfix/conf

# ── Detection rules (scan_time in seconds) ──────────────────────────────────
rules:
  auth_failed:
    max_auth_failures: 5      # SASL failures from one IP → block the IP
    scan_time: 300

  number_messages:
    max_messages: 100         # deliveries to EXTERNAL domains per account → suspend
    scan_time: 3600           # (local/internal deliveries do not count)

  sasl_connections:           # SMTP logins only (IMAP/POP3 are ignored)
    max_sasl_connections: 20  # total logins of one account → suspend
    max_unique_ips: 5         # distinct IPs logging in as one account → suspend + block them all
    scan_time: 300

  dist_brute_force:
    max_ips: 5                # distinct IPs failing against one account → notify only
    scan_time: 300

  impossible_traveler:
    window_minutes: 30        # two countries within this window → suspend + block attacker IP
    # Mail-client proxies to ignore (Outlook Mobile / Exchange Online, ...):
    trusted_cidrs:
      - "104.47.0.0/17"
    # By organization name — only with the HTTP API (ipinfo.io); with the local
    # MaxMind DB there is no org data, so it is ignored (a warning is logged).
    # trusted_orgs: ["MICROSOFT", "GOOGLE", "APPLE"]

  queue_monitor:
    queue_threshold: 2500     # deferrals to one destination domain → notify only
    scan_time: 3600           # (never purges the queue)

  domain_discovery:
    max_domains: 10           # distinct target domains of failed logins from one IP → block
    scan_time: 600

  bounce_rate:
    max_bounces: 50           # bounces caused by one account → suspend
    scan_time: 300

  rcpt_flood:
    max_recipients: 50        # recipients from one authenticated IP → block IP + suspend
    scan_time: 300

  password_spray:
    max_accounts: 10          # distinct accounts failed from one IP → block
    scan_time: 300

  account_takeover:
    min_failures: 5           # failures before an account is watched
    correl_window: 600        # failures followed by success/sending → suspend (+ block)

# ── Cloud proxies ────────────────────────────────────────────────────────────
# The IP of events from these ranges is cleared before dispatch: IP-based
# modules (auth_failed, rcpt_flood, password_spray, domain_discovery,
# impossible_traveler) ignore them, so a shared proxy is never blocked.
# Account-based counters (sasl_connections total, account_takeover) still count.
# Defaults: Microsoft 365/Exchange, Google Mail, Apple iCloud.
# proxy_cidrs: ["52.96.0.0/12", "104.47.0.0/17", "17.0.0.0/8", ...]

# ── GeoIP ────────────────────────────────────────────────────────────────────
geoip:
  # Recommended: local MaxMind GeoLite2 database (no network, no rate limits).
  # install.sh / Ansible download it and keep it updated when credentials are given.
  db_path: "/var/lib/sendguard/GeoLite2-Country.mmdb"
  maxmind_account_id: ""
  maxmind_license_key: ""
  # Fallback when db_path is empty:
  api_url: "https://ipinfo.io"  # 50k requests/month free
  token: ""                     # optional ipinfo.io token
  cache_ttl: 24                 # hours (HTTP API mode only)
  # Countries where your users normally are. IPs from these countries are
  # never contained automatically (no block/suspend) but are still notified.
  # Case-insensitive. Empty = no country-based skipping.
  allowed_countries:
    - "PE"
    - "US"

# ── AbuseIPDB (optional) ─────────────────────────────────────────────────────
abuseipdb:
  api_key: ""                 # leave blank to disable
  cache_ttl: 24               # hours

# ── Firewall ─────────────────────────────────────────────────────────────────
firewall:
  # "firewalld-ipset" (recommended on RHEL: one hash:net set bound to the drop zone)
  # "firewalld"       (one rich rule per IP; degrades with thousands of bans)
  # "ufw"             (Ubuntu/Debian)
  # Default when omitted: "firewalld". install.sh and Ansible write
  # "firewalld-ipset" on RHEL and "ufw" on Debian/Ubuntu.
  backend: "firewalld-ipset"
  ban_seconds: 3600           # 0 = permanent ban
  # Private networks (RFC 1918), loopback and link-local are never blocked.

# ── Local SQLite database ────────────────────────────────────────────────────
# Persists bans (restored and reconciled with the firewall on startup), runtime
# whitelist changes and alerts pending for the Controller. "" disables it.
local_db:
  path: "/var/lib/sendguard/sendguard.db"
  max_size_mb: 100            # informational

# ── Controller (optional) ────────────────────────────────────────────────────
# Leave url blank for standalone mode; alerts are stored locally only.
controller:
  url: ""
  api_key: ""
  sync_interval: 30           # seconds between sync attempts
  batch_size: 100             # alerts per HTTP POST

# ── Audit log ────────────────────────────────────────────────────────────────
audit_log:
  path: "/var/log/sendguard-audit.log"  # NDJSON; "" disables it

# ── HTTP API ─────────────────────────────────────────────────────────────────
api:
  listen: "127.0.0.1:9099"    # leave blank to disable the API
  # Required for write endpoints (block/unblock/unsuspend/whitelist) via the
  # X-Api-Key header. install.sh and the Ansible role generate a random key
  # automatically (also stored in /etc/sendguard/api.key for sendguard-ctl);
  # empty means ANY local process can call the write endpoints.
  api_key: ""

# ── Notifications ─────────────────────────────────────────────────────────────
# Each channel is enabled only when its required fields are set.
notification:
  telegram:
    token: ""                 # bot token
    chat_id: ""               # chat/group/channel ID
  webhook:
    url: ""                   # HTTP endpoint (Slack, Teams, n8n, ...)
    timeout: 10               # seconds
  email:                      # sent with Zimbra's local sendmail (no SMTP config)
    from: ""                  # required to enable the channel
    to: []                    # alert recipients
    sendmail_bin: "/opt/zimbra/common/sbin/sendmail"
    # Email the affected user when their account is suspended (needs only `from`).
    notify_suspended_user: false
    user_notice_from: ""      # sender/support contact of that notice ("" = from)
  cooldown_seconds: 300       # min. time between notifications for the same IP/account
  max_per_minute: 10          # global cap
  # Push only these actions (audit log, SQLite and Controller always get all).
  # Values: block_ip | suspend_account | notify_only. Empty = everything.
  on_actions: []

# ── Daily report ─────────────────────────────────────────────────────────────
daily_report:
  hour: 8                     # UTC hour; sent via notification.email

# ── Whitelist ─────────────────────────────────────────────────────────────────
# Exempt from detection. Private networks are always exempt (built in).
# Entries added at runtime with `sendguard-ctl whitelist add` are persisted in
# SQLite and kept in addition to these.
whitelist:
  ips:
    - "190.5.1.0/24"          # office network
  accounts:
    - "newsletter@example.com"
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

The agent's CLI output and logs are in Spanish:

```
SendGuard  versión: v1.2.0  uptime: 5s

Contadores:
  eventos procesados : 0
  alertas emitidas   : 0
  IPs bloqueadas     : 0
  cuentas suspendidas: 0

No hay IPs bloqueadas actualmente.
```

---

## Upgrading

Preferred: re-run the same method used to install — the Ansible playbook, the
new `.deb`/`.rpm`, or `install.sh` from the new tarball (it offers the existing
values as defaults). All three first remove the Postfix hooks of versions
< 1.1.0 (`remove_smtp_hooks.sh`) and only then replace the binaries.

Replacing the binaries by hand is only safe from **1.1.0 onwards**:

```bash
install -m 755 dist/sendguard-agent /usr/local/bin/sendguard-agent
install -m 755 dist/sendguard-ctl   /usr/local/bin/sendguard-ctl
systemctl restart sendguard-agent
systemctl status sendguard-agent
```

> Upgrading from < 1.1.0 by hand: run `sh deploy/remove_smtp_hooks.sh` first.
> Stopping `sendguard-policyd` while Postfix still points at it makes Postfix
> answer 451 to all incoming mail.

Configuration and the SQLite database at `/var/lib/sendguard/sendguard.db` are preserved across upgrades. Active bans are restored from the database on startup and re-applied in the firewall if missing.

---

## Uninstalling

If installed from a **package**, use the package manager (config and database in
`/etc/sendguard` and `/var/lib/sendguard` are preserved):

```bash
apt remove sendguard      # Debian/Ubuntu (agent.yaml is not a package file: purge keeps it too)
dnf remove sendguard      # RHEL/Rocky/AlmaLinux

# To remove the preserved config and database as well:
rm -rf /etc/sendguard /var/lib/sendguard
```

If installed from the **tarball/`install.sh`**, use the bundled script:

```bash
bash uninstall.sh
```

It asks for confirmation and, in order:

1. Removes the Postfix hooks of versions < 1.1.0, if any.
2. While the agent is still running, asks it to unblock every IP it banned.
3. Deletes the `sendguard` ipset.
4. Stops the service and removes the binaries, config, database, audit log and GeoIP cron.

Remaining `deny`/`reject` rules that cannot be attributed to SendGuard with certainty are only listed, never deleted — they may belong to the administrator.

> Package removal (`apt/dnf remove`) does not unblock IPs. Run
> `sendguard-ctl status` and `sendguard-ctl unblock <ip>` first, or remove the
> ipset afterwards (`firewall-cmd --permanent --zone=drop --remove-source=ipset:sendguard`,
> `firewall-cmd --permanent --delete-ipset=sendguard`, `firewall-cmd --reload`).

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
2. Check that the firewall backend matches the OS: `firewall.backend: "ufw"` on Ubuntu, `"firewalld-ipset"` (or `"firewalld"`) on RHEL.
3. Check whether the source IP is from a country in `geoip.allowed_countries`: automatic containment is skipped for those (the alert is notified with "contención omitida").
4. Lower the detection thresholds temporarily and watch `journalctl -u sendguard-agent -f` for `enforcement: IP bloqueada` or `enforcement: cuenta suspendida` messages.
5. Verify the whitelist is not covering the test IP: `sendguard-ctl whitelist list` (private networks are always exempt)

### firewalld: rules are not being added

```bash
systemctl is-active firewalld
firewall-cmd --state
# Backend firewalld-ipset: entries of the set and its binding to the drop zone
firewall-cmd --ipset=sendguard --get-entries
firewall-cmd --zone=drop --list-sources        # must include ipset:sendguard
# Backend firewalld (rich rules)
firewall-cmd --list-rich-rules
```

After a `firewall-cmd --reload` or a firewalld restart, temporary bans vanish
from the firewall; the agent re-applies them within 2 minutes (look for
`bans ausentes en el firewall re-aplicados` in the journal).

### ufw: rules are not being added

```bash
ufw status          # SendGuard bans appear as "Anywhere  DENY  <ip>"
# Verify the agent can call ufw
ufw --dry-run deny from 1.2.3.4 to any
# Confirm ufw is active
ufw status | grep "Status:"
```

### Telegram notifications not arriving

1. Confirm `notification.telegram.token` and `chat_id` are set.
2. Test the bot token manually:
   ```bash
   curl -s "https://api.telegram.org/bot<TOKEN>/getMe"
   ```
3. Make sure the bot has been added to the target chat and has permission to post.

### API returns 401

As root, `sendguard-ctl` reads the key from `/etc/sendguard/api.key` automatically
(or from `$SENDGUARD_API_KEY`). A 401 usually means that file is missing or stale —
check that it matches `api.api_key` in `agent.yaml`. You can always pass the key
explicitly:
```bash
sendguard-ctl -addr http://127.0.0.1:9099 -key your-api-key block 1.2.3.4
```

Or via `curl`:
```bash
curl -H "X-Api-Key: your-api-key" -X POST http://127.0.0.1:9099/blocked/1.2.3.4
```

### Bans not surviving restarts

Ensure `local_db.path` points to a writable location (with `local_db.path` empty, bans are rebuilt from the firewall rules instead). On first start, SendGuard creates the SQLite file automatically. Check:
```bash
ls -lh /var/lib/sendguard/sendguard.db
```
