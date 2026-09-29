#!/usr/bin/env bash
# SendGuard Agent — desinstalación completa del servidor Zimbra
# Elimina binarios, servicios systemd, configuración y base de datos local.
# Los bans activos en el firewall se limpian automáticamente.
# Uso: bash uninstall.sh
# Requiere: root
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${CYAN}  →${NC} $*"; }
ok()      { echo -e "${GREEN}  ✓${NC} $*"; }
warn()    { echo -e "${YELLOW}  !${NC} $*"; }
section() { echo -e "\n${BOLD}$*${NC}"; }

[[ $EUID -eq 0 ]] || { echo -e "${RED}  ✗${NC} Ejecutar como root (sudo bash uninstall.sh)" >&2; exit 1; }

# ── Confirmación ──────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}SendGuard — Desinstalación${NC}"
echo ""
echo "  Se eliminarán:"
echo "    /usr/local/bin/sendguard-agent"
echo "    /usr/local/bin/sendguard-ctl"
echo "    /usr/local/lib/sendguard/"
echo "    /etc/systemd/system/sendguard-agent.service"
echo "    sendguard-policyd y su hook en Postfix (instalaciones <1.1.0)"
echo "    /etc/sendguard/          (configuración)"
echo "    /var/lib/sendguard/      (base de datos SQLite + GeoIP)"
echo "    /var/log/sendguard-audit.log"
echo "    cron de actualización GeoIP (si existe)"
echo ""
echo "  Los bans activos del agente se desbloquearán y se eliminará el ipset 'sendguard'."
echo ""
read -rp "  ¿Confirmar desinstalación? [s/N]: " CONFIRM
[[ "${CONFIRM,,}" == "s" ]] || { echo "  Cancelado."; exit 0; }

# ── Retiro de la integración SMTP heredada ────────────────────────────────────
# Instalaciones <1.1.0: hay que quitar check_policy_service de Postfix ANTES de
# detener sendguard-policyd, o Postfix rechaza con 451 todo el correo entrante.
section "── Integración SMTP heredada"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOOKS_SCRIPT=""
for f in "$SCRIPT_DIR/remove_smtp_hooks.sh" /usr/local/lib/sendguard/remove_smtp_hooks.sh; do
    [[ -f "$f" ]] && { HOOKS_SCRIPT="$f"; break; }
done
if [[ -n "$HOOKS_SCRIPT" ]]; then
    if ! sh "$HOOKS_SCRIPT"; then
        echo -e "${RED}  ✗${NC} No se pudo retirar el hook de SendGuard en Postfix; se aborta sin tocar nada más." >&2
        exit 1
    fi
    ok "Postfix sin hooks de SendGuard"
elif systemctl is-active --quiet sendguard-policyd 2>/dev/null; then
    echo -e "${RED}  ✗${NC} sendguard-policyd activo y falta remove_smtp_hooks.sh: detenerlo cortaría el correo. Abortando." >&2
    exit 1
fi

# ── Limpiar bans del firewall ─────────────────────────────────────────────────
# Con el agente todavía corriendo: él sabe exactamente qué IPs bloqueó y con qué
# backend, así que se le pide desbloquear cada una (firewall + SQLite). No se
# borran reglas por su forma: un "deny"/"reject" del administrador se vería
# igual. Lo único que se elimina en bloque es el ipset "sendguard", que es
# enteramente de SendGuard.
section "── Bans del firewall"

API_ADDR=127.0.0.1:9099
CTL=/usr/local/bin/sendguard-ctl
if [[ -x "$CTL" ]] && curl -fsS -o /dev/null --max-time 5 "http://$API_ADDR/health" 2>/dev/null; then
    AGENT_IPS=$(curl -fsS --max-time 10 "http://$API_ADDR/status" 2>/dev/null \
        | grep -oE '"ip":"[^"]+"' | cut -d'"' -f4 || true)
    n=0
    for ip in $AGENT_IPS; do
        if "$CTL" -addr "http://$API_ADDR" unblock "$ip" &>/dev/null; then
            n=$((n + 1))
        else
            warn "No se pudo desbloquear $ip vía el agente"
        fi
    done
    ok "Bans del agente desbloqueados: $n"
else
    warn "El agente no responde en $API_ADDR: no se pueden identificar sus bans con certeza"
fi

if systemctl is-active --quiet firewalld 2>/dev/null; then
    # Backend firewalld-ipset: quitar el binding de la zona drop y el set.
    if firewall-cmd --permanent --get-ipsets 2>/dev/null | tr ' ' '\n' | grep -qx sendguard; then
        firewall-cmd --permanent --zone=drop --remove-source=ipset:sendguard &>/dev/null || true
        firewall-cmd --permanent --delete-ipset=sendguard &>/dev/null \
            && ok "ipset 'sendguard' eliminado" \
            || warn "No se pudo eliminar el ipset 'sendguard' — revísalo con: firewall-cmd --get-ipsets"
        firewall-cmd --reload &>/dev/null || true
    fi
    # Backend firewalld (rich rules): informar las que queden con la forma de
    # SendGuard, sin borrarlas (pueden ser del administrador).
    LEFT=$( { firewall-cmd --list-rich-rules; firewall-cmd --permanent --list-rich-rules; } 2>/dev/null \
        | grep -E '^rule family="?ipv4"? source address="?[^" ]+"? reject$' | sort -u || true)
    if [[ -n "$LEFT" ]]; then
        warn "Quedan rich rules 'reject' con la forma que usaba SendGuard (revisar y borrar a mano si corresponde):"
        echo "$LEFT" | sed 's/^/      /'
    fi
elif command -v ufw &>/dev/null; then
    LEFT=$(ufw status 2>/dev/null | awk '$1=="Anywhere" && $2=="DENY" && ($3=="IN" ? $4 : $3) ~ /^[0-9.\/]+$/' || true)
    if [[ -n "$LEFT" ]]; then
        warn "Quedan reglas ufw 'deny from X' (pueden ser de SendGuard o del administrador; revisar a mano):"
        echo "$LEFT" | sed 's/^/      /'
    fi
else
    warn "No se detectó firewalld ni ufw — limpia los bans manualmente"
fi

# ── Detener y deshabilitar servicios ──────────────────────────────────────────
section "── Servicios systemd"

if systemctl is-active --quiet sendguard-agent 2>/dev/null; then
    systemctl stop sendguard-agent
    ok "sendguard-agent detenido"
else
    info "sendguard-agent no estaba corriendo"
fi
if systemctl is-enabled --quiet sendguard-agent 2>/dev/null; then
    systemctl disable sendguard-agent
    ok "sendguard-agent deshabilitado"
fi

# ── Eliminar archivos de servicio systemd ─────────────────────────────────────
section "── Archivos systemd"

if [[ -f /etc/systemd/system/sendguard-agent.service ]]; then
    rm -f /etc/systemd/system/sendguard-agent.service
    ok "Eliminado: /etc/systemd/system/sendguard-agent.service"
fi
systemctl daemon-reload
ok "systemd recargado"

# ── Eliminar binarios ─────────────────────────────────────────────────────────
section "── Binarios"

for bin in /usr/local/bin/sendguard-agent \
           /usr/local/bin/sendguard-ctl; do
    if [[ -f "$bin" ]]; then
        rm -f "$bin"
        ok "Eliminado: $bin"
    fi
done
if [[ -d /usr/local/lib/sendguard ]]; then
    rm -rf /usr/local/lib/sendguard
    ok "Eliminado: /usr/local/lib/sendguard/"
fi

# ── Eliminar configuración y datos ────────────────────────────────────────────
section "── Configuración y datos"

if [[ -d /etc/sendguard ]]; then
    rm -rf /etc/sendguard
    ok "Eliminado: /etc/sendguard/"
fi

if [[ -d /var/lib/sendguard ]]; then
    rm -rf /var/lib/sendguard
    ok "Eliminado: /var/lib/sendguard/"
fi

if [[ -f /var/log/sendguard-audit.log ]]; then
    rm -f /var/log/sendguard-audit.log
    ok "Eliminado: /var/log/sendguard-audit.log"
fi

# ── Eliminar cron de GeoIP ────────────────────────────────────────────────────
section "── Cron de actualización GeoIP"

if crontab -l 2>/dev/null | grep -q 'SendGuard GeoIP update'; then
    (crontab -l 2>/dev/null | grep -v 'SendGuard GeoIP update') | crontab -
    ok "Cron de GeoIP eliminado"
else
    info "No había cron de GeoIP"
fi

# ── Resumen ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}══════════════════════════════════════════════${NC}"
echo -e "${GREEN}  SendGuard desinstalado correctamente${NC}"
echo -e "${BOLD}══════════════════════════════════════════════${NC}"
echo ""
