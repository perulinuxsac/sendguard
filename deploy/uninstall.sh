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
echo "  Los bans activos en el firewall serán eliminados."
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

# ── Detener y deshabilitar servicios ──────────────────────────────────────────
section "── Servicios systemd"

for svc in sendguard-agent; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        systemctl stop "$svc"
        ok "$svc detenido"
    else
        info "$svc no estaba corriendo"
    fi
    if systemctl is-enabled --quiet "$svc" 2>/dev/null; then
        systemctl disable "$svc"
        ok "$svc deshabilitado"
    fi
done

# ── Limpiar bans del firewall ─────────────────────────────────────────────────
section "── Bans del firewall"

# Detectar backend activo
if systemctl is-active --quiet firewalld 2>/dev/null; then
    # firewalld: eliminar reglas de la zona sendguard si existe
    if firewall-cmd --get-zones 2>/dev/null | grep -qw sendguard; then
        BLOCKED_IPS=$(firewall-cmd --zone=sendguard --list-rich-rules 2>/dev/null \
            | grep -oP '(?<=source address=")[^"]+' || true)
        for ip in $BLOCKED_IPS; do
            firewall-cmd --zone=sendguard --remove-rich-rule="rule family='ipv4' source address='$ip' drop" \
                --permanent &>/dev/null && info "IP eliminada del firewall: $ip"
        done
        firewall-cmd --reload &>/dev/null || true
        ok "Bans de firewalld eliminados"
    else
        # Zona default: buscar reglas rich con "SendGuard" o limpiar la zona drop
        BLOCKED_IPS=$(firewall-cmd --zone=drop --list-rich-rules 2>/dev/null \
            | grep -oP '(?<=source address=")[^"]+' || true)
        for ip in $BLOCKED_IPS; do
            firewall-cmd --zone=drop --remove-rich-rule="rule family='ipv4' source address='$ip' drop" \
                --permanent &>/dev/null && info "IP eliminada del firewall: $ip"
        done
        [[ -n "$BLOCKED_IPS" ]] && firewall-cmd --reload &>/dev/null || true
        ok "Bans de firewalld procesados"
    fi
elif command -v ufw &>/dev/null; then
    # ufw: eliminar reglas DENY TO con comentario sendguard (si las hay)
    ufw status numbered 2>/dev/null | grep -i 'DENY IN' | awk '{print $1}' | tr -d '[]' \
        | sort -rn | while read -r n; do
        ufw --force delete "$n" &>/dev/null && info "Regla ufw #$n eliminada"
    done
    ok "Bans de ufw procesados (revisar manualmente si persisten reglas)"
else
    warn "No se detectó firewalld ni ufw — limpia los bans manualmente"
fi

# ── Eliminar archivos de servicio systemd ─────────────────────────────────────
section "── Archivos systemd"

for f in /etc/systemd/system/sendguard-agent.service; do
    if [[ -f "$f" ]]; then
        rm -f "$f"
        ok "Eliminado: $f"
    fi
done
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
