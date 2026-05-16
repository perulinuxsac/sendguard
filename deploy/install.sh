#!/usr/bin/env bash
# SendGuard Agent — instalación en servidor Zimbra del cliente
# Soporta: RHEL/CentOS/Rocky/AlmaLinux (firewalld) y Ubuntu/Debian (ufw)
# Uso: bash install.sh
# Requiere: root, systemd
set -euo pipefail

# ── Colores ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${CYAN}  →${NC} $*"; }
ok()      { echo -e "${GREEN}  ✓${NC} $*"; }
warn()    { echo -e "${YELLOW}  !${NC} $*"; }
die()     { echo -e "${RED}  ✗${NC} $*" >&2; exit 1; }
section() { echo -e "\n${BOLD}$*${NC}"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Cargar os-release al nivel del script para que PRETTY_NAME esté disponible.
# shellcheck disable=SC1091
[[ -f /etc/os-release ]] && . /etc/os-release

# ── Constantes ────────────────────────────────────────────────────────────────
BIN_AGENT=/usr/local/bin/sendguard-agent
BIN_CTL=/usr/local/bin/sendguard-ctl
SERVICE_FILE=/etc/systemd/system/sendguard-agent.service
CONFIG_FILE=/etc/sendguard/agent.yaml
DB_DIR=/var/lib/sendguard
API_ADDR=127.0.0.1:9099

# ── Detectar distribución ─────────────────────────────────────────────────────
detect_os() {
    local id="" id_like=""
    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        id="${ID:-}"
        id_like="${ID_LIKE:-}"
    fi

    case "$id" in
        ubuntu|debian|linuxmint|pop)
            echo "debian" ;;
        rhel|centos|rocky|almalinux|fedora|ol)
            echo "rhel" ;;
        *)
            # Fallback: revisar ID_LIKE
            if [[ "$id_like" == *debian* || "$id_like" == *ubuntu* ]]; then
                echo "debian"
            elif [[ "$id_like" == *rhel* || "$id_like" == *fedora* || "$id_like" == *centos* ]]; then
                echo "rhel"
            else
                echo "unknown"
            fi
            ;;
    esac
}

# ── Verificaciones previas ────────────────────────────────────────────────────
section "── Verificaciones previas"

[[ $EUID -eq 0 ]] || die "Ejecutar como root (sudo bash install.sh)"
ok "root"

command -v systemctl &>/dev/null || die "systemd no encontrado"
ok "systemd"

OS_FAMILY=$(detect_os)
info "Distribución detectada: ${PRETTY_NAME:-$OS_FAMILY}"

# Seleccionar backend de firewall según distro
case "$OS_FAMILY" in
    debian)
        FIREWALL_BACKEND="ufw"
        command -v ufw &>/dev/null          || die "ufw no instalado (apt install ufw)"
        ufw status | grep -q "Status: active" || die "ufw no está activo (ufw enable)"
        ok "firewall: ufw activo"
        ;;
    rhel)
        FIREWALL_BACKEND="firewalld"
        systemctl is-active --quiet firewalld || die "firewalld no está activo (systemctl start firewalld)"
        ok "firewall: firewalld activo"
        ;;
    *)
        warn "Distribución no reconocida — asumiendo firewalld"
        FIREWALL_BACKEND="firewalld"
        systemctl is-active --quiet firewalld || die "firewalld no está activo (systemctl start firewalld)"
        ok "firewall: firewalld activo"
        ;;
esac

# Detectar rutas de Zimbra
ZIMBRA_SBIN=""
ZIMBRA_CONF=""
for p in /opt/zimbra/common/sbin /opt/zimbra/postfix/sbin; do
    [[ -d "$p" ]] && ZIMBRA_SBIN="$p" && break
done
for p in /opt/zimbra/common/conf /opt/zimbra/postfix/conf; do
    [[ -d "$p" ]] && ZIMBRA_CONF="$p" && break
done
[[ -n "$ZIMBRA_SBIN" ]] || die "No se encontró Zimbra en /opt/zimbra"
ok "Zimbra detectado: $ZIMBRA_SBIN"

# Detectar log principal según distro
MAIL_LOG=""
case "$OS_FAMILY" in
    debian)
        # Ubuntu/Debian: /var/log/mail.log
        [[ -f /var/log/mail.log ]] && MAIL_LOG=/var/log/mail.log ;;
    rhel)
        # RHEL/CentOS/Rocky: /var/log/maillog
        [[ -f /var/log/maillog ]] && MAIL_LOG=/var/log/maillog ;;
esac
# Fallback: buscar en ambas rutas
if [[ -z "$MAIL_LOG" ]]; then
    for p in /var/log/mail.log /var/log/maillog; do
        [[ -f "$p" ]] && MAIL_LOG="$p" && break
    done
fi
[[ -n "$MAIL_LOG" ]] || die "No se encontró mail.log (/var/log/mail.log o /var/log/maillog)"
ok "Log principal: $MAIL_LOG"

# Mailbox log (opcional)
MAILBOX_LOG=""
[[ -f /opt/zimbra/log/mailbox.log ]] && MAILBOX_LOG="/opt/zimbra/log/mailbox.log"

# ── Binarios ──────────────────────────────────────────────────────────────────
section "── Instalación de binarios"

for bin in sendguard-agent sendguard-ctl; do
    dst="/usr/local/bin/$bin"
    # Buscar en: mismo dir (tar.gz plano) → ../dist/ (repo dev) → ya instalado
    if [[ -f "$SCRIPT_DIR/$bin" ]]; then
        install -m 755 "$SCRIPT_DIR/$bin" "$dst"
        ok "$dst instalado"
    elif [[ -f "$SCRIPT_DIR/../dist/$bin" ]]; then
        install -m 755 "$SCRIPT_DIR/../dist/$bin" "$dst"
        ok "$dst instalado desde dist/"
    elif [[ -f "$dst" ]]; then
        ok "$dst ya presente"
    else
        die "Binario no encontrado: compila primero con 'make build build-ctl'"
    fi
done

# ── Configuración interactiva ─────────────────────────────────────────────────
section "── Configuración del cliente"

ask() {
    local prompt="$1" default="$2" var_name="$3"
    local input
    if [[ -n "$default" ]]; then
        read -rp "  ${prompt} [${default}]: " input
        printf -v "$var_name" '%s' "${input:-$default}"
    else
        read -rp "  ${prompt}: " input
        printf -v "$var_name" '%s' "$input"
    fi
}

ask "ID del servidor (ej: cliente-abc-mail1)"   "$(hostname -s)-mail1"  SERVER_ID
ask "Nombre del cliente (ej: Laboratorios ABC)" ""                       CLIENT_NAME
[[ -n "$CLIENT_NAME" ]] || die "El nombre del cliente es obligatorio"

ask "Países permitidos, separados por coma (ej: PE,US)"  "PE"  COUNTRIES_RAW

ask "Redes de oficina en whitelist (CIDR, separadas por coma, vacío para omitir)"  ""  WL_IPS_RAW
ask "Cuentas en whitelist (vacío para omitir)"                                      ""  WL_ACCTS_RAW

echo ""
info "Notificaciones Telegram (dejar vacío para omitir)"
ask "Token del bot"  ""  TG_TOKEN
TG_CHAT_ID=""
[[ -n "$TG_TOKEN" ]] && ask "Chat ID"  ""  TG_CHAT_ID

ask "URL del Controller central (vacío = standalone)"  ""  CTRL_URL
CTRL_KEY=""
[[ -n "$CTRL_URL" ]] && ask "API Key del Controller"  ""  CTRL_KEY

echo ""
info "Notificaciones por Email (usa sendmail de Zimbra — sin configuración SMTP)"
ask "Correo remitente (from, vacío para omitir)"  ""  EMAIL_FROM
EMAIL_TO=""
[[ -n "$EMAIL_FROM" ]] && ask "Destinatarios (separados por coma)"  ""  EMAIL_TO

echo ""
info "AbuseIPDB (enriquece alertas con reputación de IPs — registro gratuito en abuseipdb.com)"
ask "API Key de AbuseIPDB (vacío para omitir)"  ""  ABUSEIPDB_KEY

echo ""
info "GeoIP local MaxMind (recomendado para producción, evita rate-limits)"
info "Registro gratuito en: https://www.maxmind.com/en/geolite2/signup"
info "Account ID y License Key se encuentran en: maxmind.com → My Account → Manage License Keys"
ask "Account ID de MaxMind (número, vacío = usar HTTP API)"  ""  MM_ACCOUNT_ID
MM_LICENSE_KEY=""
[[ -n "$MM_ACCOUNT_ID" ]] && ask "License Key de MaxMind"  ""  MM_LICENSE_KEY

# ── Generar YAML ──────────────────────────────────────────────────────────────
section "── Generando configuración"

# Convertir países a lista YAML
COUNTRIES_YAML=""
IFS=',' read -ra CTRY_ARR <<< "$COUNTRIES_RAW"
for c in "${CTRY_ARR[@]}"; do
    c="${c// /}"
    COUNTRIES_YAML+=$'\n    - "'"$c"'"'
done

# Convertir IPs a lista YAML
IPS_YAML=""
if [[ -n "$WL_IPS_RAW" ]]; then
    IFS=',' read -ra IP_ARR <<< "$WL_IPS_RAW"
    for ip in "${IP_ARR[@]}"; do
        ip="${ip// /}"
        IPS_YAML+=$'\n    - "'"$ip"'"'
    done
fi

# Convertir cuentas a lista YAML
ACCTS_YAML=""
if [[ -n "$WL_ACCTS_RAW" ]]; then
    IFS=',' read -ra ACCT_ARR <<< "$WL_ACCTS_RAW"
    for a in "${ACCT_ARR[@]}"; do
        a="${a// /}"
        ACCTS_YAML+=$'\n    - "'"$a"'"'
    done
fi

MAILBOX_LINE=""
[[ -n "$MAILBOX_LOG" ]] && MAILBOX_LINE="    mailbox: \"$MAILBOX_LOG\""

# Convertir destinatarios email a lista YAML
EMAIL_TO_YAML=""
if [[ -n "$EMAIL_TO" ]]; then
    IFS=',' read -ra TO_ARR <<< "$EMAIL_TO"
    for addr in "${TO_ARR[@]}"; do
        addr="${addr// /}"
        EMAIL_TO_YAML+=$'\n    - "'"$addr"'"'
    done
fi

# Pre-asignar defaults aquí: $'...' no se expande dentro de heredoc
[[ -z "$ACCTS_YAML" ]] && ACCTS_YAML=$'\n    []'
[[ -z "$IPS_YAML" ]]   && IPS_YAML=$'\n    []'

mkdir -p /etc/sendguard "$DB_DIR"
chmod 750 /etc/sendguard "$DB_DIR"

# Descargar GeoLite2-Country.mmdb si se proporcionó license key
MMDB_PATH=""
GEOIP_DB_LINE="  # db_path no configurado — usando HTTP API fallback"
if [[ -n "$MM_ACCOUNT_ID" && -n "$MM_LICENSE_KEY" ]]; then
    # MaxMind usa HTTP Basic Auth: usuario=account_id, contraseña=license_key
    MMDB_URL="https://download.maxmind.com/geoip/databases/GeoLite2-Country/download?suffix=tar.gz"
    MMDB_TAR="$DB_DIR/GeoLite2-Country.tar.gz"
    MMDB_PATH="$DB_DIR/GeoLite2-Country.mmdb"
    info "Descargando GeoLite2-Country.mmdb..."
    if curl -fsSL -u "${MM_ACCOUNT_ID}:${MM_LICENSE_KEY}" "$MMDB_URL" -o "$MMDB_TAR" 2>/dev/null; then
        tar -xzf "$MMDB_TAR" --wildcards --strip-components=1 -C "$DB_DIR" '*.mmdb' 2>/dev/null \
            && rm -f "$MMDB_TAR" \
            && ok "GeoLite2-Country.mmdb instalado en $MMDB_PATH" \
            && GEOIP_DB_LINE="  db_path: \"$MMDB_PATH\"" \
            || { warn "Error extrayendo mmdb — se usará HTTP API"; MMDB_PATH=""; }
    else
        warn "No se pudo descargar la DB (credenciales inválidas o sin acceso a internet) — se usará HTTP API"
        MMDB_PATH=""
    fi

    # Cron semanal de actualización (jueves 3am, MaxMind actualiza martes/viernes)
    if [[ -n "$MMDB_PATH" ]]; then
        CRON_CMD="curl -fsSL -u '${MM_ACCOUNT_ID}:${MM_LICENSE_KEY}' '${MMDB_URL}' -o '${MMDB_TAR}' && tar -xzf '${MMDB_TAR}' --wildcards --strip-components=1 -C '${DB_DIR}' '*.mmdb' && rm -f '${MMDB_TAR}' && systemctl reload-or-restart sendguard-agent"
        (crontab -l 2>/dev/null | grep -v 'GeoLite2-Country'; echo "0 3 * * 4 $CRON_CMD # SendGuard GeoIP update") | crontab -
        ok "Cron de actualización GeoIP instalado (jueves 3am)"
    fi
fi

cat > "$CONFIG_FILE" << YAML
server_id: "${SERVER_ID}"
client_name: "${CLIENT_NAME}"

controller:
  url: "${CTRL_URL}"
  api_key: "${CTRL_KEY}"
  sync_interval: 30
  batch_size: 100

zimbra:
  logs:
    main: "${MAIL_LOG}"
${MAILBOX_LINE}
  workers: 4
  postfix_sbin: "${ZIMBRA_SBIN}"
  postfix_conf: "${ZIMBRA_CONF}"

rules:
  auth_failed:
    max_auth_failures: 5
    scan_time: 300
  number_messages:
    max_messages: 300
    scan_time: 3600
  sasl_connections:
    max_sasl_connections: 20
    max_unique_ips: 5
    scan_time: 300
  dist_brute_force:
    max_ips: 5
    scan_time: 300
  impossible_traveler:
    window_minutes: 30
    # trusted_orgs: detección por nombre de organización via ipinfo.io (recomendado).
    # Cubre TODAS las IPs de cada proveedor sin importar cuántas tengan.
    trusted_orgs:
      - "MICROSOFT"   # Outlook Mobile, Exchange Online, Azure
      - "GOOGLE"      # Gmail Mobile, Google Workspace
      - "APPLE"       # iCloud Mail, Apple Mail Mobile
      - "AMAZON"      # AWS SES, WorkMail
    # trusted_cidrs: red de seguridad para modo DB local (sin llamadas a ipinfo.io).
    # Solo los rangos principales de Exchange Online para IMAP/SMTP proxy.
    trusted_cidrs:
      - "52.96.0.0/14"    # Exchange Online
      - "52.100.0.0/14"   # Exchange Online
      - "52.104.0.0/14"   # Exchange Online
      - "52.108.0.0/14"   # Exchange Online
      - "104.47.0.0/17"   # Exchange Online Protection
  queue_monitor:
    queue_threshold: 2500
    scan_time: 3600
  domain_discovery:
    max_domains: 10
    scan_time: 600
  bounce_rate:
    max_bounces: 50
    scan_time: 300
  rcpt_flood:
    max_recipients: 50
    scan_time: 300
  password_spray:
    max_accounts: 10
    scan_time: 300

geoip:
${GEOIP_DB_LINE}
  api_url: "https://ipinfo.io"
  cache_ttl: 24
  allowed_countries:${COUNTRIES_YAML}

local_db:
  path: "${DB_DIR}/sendguard.db"
  max_size_mb: 100

firewall:
  backend: "${FIREWALL_BACKEND}"
  ban_seconds: 3600

api:
  listen: "${API_ADDR}"

abuseipdb:
  api_key: "${ABUSEIPDB_KEY}"
  cache_ttl: 24

notification:
  telegram:
    token: "${TG_TOKEN}"
    chat_id: "${TG_CHAT_ID}"
  email:
    from: "${EMAIL_FROM}"
    to:${EMAIL_TO_YAML}
  cooldown_seconds: 300
  max_per_minute: 10

daily_report:
  hour: 8

whitelist:
  accounts:${ACCTS_YAML}
  ips:${IPS_YAML}
YAML

chmod 640 "$CONFIG_FILE"
ok "Configuración escrita en $CONFIG_FILE (firewall: $FIREWALL_BACKEND)"

# ── Servicio systemd ───────────────────────────────────────────────────────────
section "── Servicio systemd"

install -m 644 "$SCRIPT_DIR/sendguard-agent.service" "$SERVICE_FILE"
ok "Servicio instalado en $SERVICE_FILE"

systemctl daemon-reload
systemctl enable sendguard-agent
ok "sendguard-agent habilitado para arrancar con el sistema"

if systemctl is-active --quiet sendguard-agent; then
    systemctl restart sendguard-agent
    ok "Servicio reiniciado"
else
    systemctl start sendguard-agent
    ok "Servicio iniciado"
fi

# ── Verificación ──────────────────────────────────────────────────────────────
section "── Verificación"

sleep 2

if systemctl is-active --quiet sendguard-agent; then
    ok "sendguard-agent está corriendo"
else
    warn "El servicio no arrancó — revisa: journalctl -u sendguard-agent -n 30"
    exit 1
fi

if $BIN_CTL -addr "http://$API_ADDR" status &>/dev/null; then
    ok "API responde en http://$API_ADDR"
    $BIN_CTL -addr "http://$API_ADDR" status
else
    warn "La API no responde todavía (puede tardar unos segundos)"
fi

# ── Resumen final ─────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}══════════════════════════════════════════════${NC}"
echo -e "${GREEN}  SendGuard instalado correctamente${NC}"
echo -e "${BOLD}══════════════════════════════════════════════${NC}"
echo ""
echo "  Servidor  :  $SERVER_ID"
echo "  Cliente   :  $CLIENT_NAME"
echo "  SO / FW   :  $OS_FAMILY / $FIREWALL_BACKEND"
echo "  Log mail  :  $MAIL_LOG"
echo "  Config    :  $CONFIG_FILE"
echo "  Base datos:  $DB_DIR/sendguard.db"
echo "  API       :  http://$API_ADDR"
echo ""
echo "  Comandos útiles:"
echo "    journalctl -u sendguard-agent -f                    # logs en vivo"
echo "    sendguard-ctl -addr http://$API_ADDR status         # estado + IPs bloqueadas"
echo "    sendguard-ctl -addr http://$API_ADDR whitelist list # whitelist activa"
echo ""
[[ -n "$CTRL_URL" ]] \
    && echo "  Controller: $CTRL_URL" \
    || echo "  Modo standalone — eventos guardados en SQLite local."
echo ""
