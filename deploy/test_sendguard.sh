#!/usr/bin/env bash
# SendGuard — Validación integral de módulos de detección
#
# Gestiona umbrales automáticamente: aplica valores bajos para prueba,
# reinicia el agente, ejecuta todos los tests y restaura la configuración
# de producción al finalizar (incluso si ocurre un error).
#
# Uso:
#   sudo bash test_sendguard.sh
#
# Seguimiento en paralelo (otra terminal):
#   journalctl -u sendguard-agent -f -o cat

set -euo pipefail

CONFIG=/etc/sendguard/agent.yaml
PAUSE=8   # segundos de espera tras inyección de logs

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

ok()      { echo -e "${GREEN}  ✓${NC} $*"; }
warn()    { echo -e "${YELLOW}  ⚠${NC} $*"; }
info()    { echo -e "${CYAN}  →${NC} $*"; }
fail()    { echo -e "${RED}  ✗${NC} $*"; }
sep()     { echo ""; echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; }

# Timestamp del inicio de cada test (actualizado antes de cada inyección).
TEST_SINCE="$(date '+%Y-%m-%d %H:%M:%S')"

mark_time() {
    sleep 0.5
    TEST_SINCE="$(date '+%Y-%m-%d %H:%M:%S')"
}

# Busca un patrón en el log del agente desde el último mark_time().
agent_log() {
    journalctl -u sendguard-agent --since="$TEST_SINCE" -o cat --no-pager 2>/dev/null
}

check_module() {
    local module="$1"
    agent_log | grep -q "\"module\":\"$module\""
}

dump_agent_log() {
    echo ""
    echo "  --- últimas líneas del agente desde el test ---"
    agent_log | tail -20 | sed 's/^/    /'
    echo "  ------------------------------------------------"
}

# ── Verificar root ────────────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || { fail "Ejecutar como root: sudo bash $0"; exit 1; }

sep
echo -e "${BOLD}SendGuard — Validación integral de módulos${NC}"
echo "$(date '+%Y-%m-%d %H:%M:%S')"
sep

# ── Pre-flight: agente activo ─────────────────────────────────────────────────
if ! systemctl is-active --quiet sendguard-agent; then
    fail "sendguard-agent no está corriendo. Inícialo con: systemctl start sendguard-agent"
    exit 1
fi
ok "sendguard-agent activo"

VERSION=$(journalctl -u sendguard-agent -n 50 --no-pager -o cat 2>/dev/null | \
    grep '"msg":"sendguard agent iniciando"' | tail -1 | \
    grep -oP '"version":"\K[^"]+' || echo "desconocida")
ok "versión en log: $VERSION"

# ── Pre-flight: verificar pipeline logger → mail.log ─────────────────────────
sep
echo -e "${BOLD}▶ Pre-check: pipeline logger → /var/log/mail.log${NC}"

PREFLIGHT_TAG="SGTEST_$$_$(date +%s)"
logger -p mail.warn -t "postfix/smtpd[9900]" \
    "warning: unknown[192.0.2.254]: SASL LOGIN authentication failed: $PREFLIGHT_TAG"
sleep 2

if grep -q "$PREFLIGHT_TAG" /var/log/mail.log 2>/dev/null; then
    ok "logger → /var/log/mail.log funciona correctamente"
else
    fail "Los mensajes de 'logger' NO llegan a /var/log/mail.log"
    echo ""
    echo "  Diagnóstico:"
    echo "    systemctl status rsyslog"
    echo "    grep -r 'mail\\.\\*\\|mail\\.warn' /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null"
    echo ""
    echo "  Solución rápida (Ubuntu 22.04):"
    echo "    echo 'mail.*  -/var/log/mail.log' > /etc/rsyslog.d/10-mail.conf"
    echo "    systemctl restart rsyslog"
    echo "    Luego vuelve a ejecutar este script."
    exit 1
fi

# ── Guardar umbrales actuales ─────────────────────────────────────────────────
sep
echo -e "${BOLD}▶ Guardando umbrales de producción y aplicando umbrales de prueba${NC}"

_get() { grep "^  *$1:" $CONFIG 2>/dev/null | awk '{print $2}' | head -1; }

OLD_AUTH_FAILURES=$(_get max_auth_failures)
OLD_MAX_MESSAGES=$(_get max_messages)
OLD_MAX_UNIQUE_IPS=$(_get max_unique_ips)
OLD_MAX_IPS=$(_get max_ips)
OLD_MAX_RECIPIENTS=$(_get max_recipients)
OLD_MAX_BOUNCES=$(_get max_bounces)
OLD_QUEUE_THRESHOLD=$(_get queue_threshold)

info "Producción: failures=${OLD_AUTH_FAILURES:--} messages=${OLD_MAX_MESSAGES:--} unique_ips=${OLD_MAX_UNIQUE_IPS:--} ips=${OLD_MAX_IPS:--} recipients=${OLD_MAX_RECIPIENTS:--} bounces=${OLD_MAX_BOUNCES:--} queue=${OLD_QUEUE_THRESHOLD:--}"

# Función de restauración ejecutada siempre al salir (EXIT trap).
restore_production() {
    sep
    echo -e "${BOLD}Restaurando configuración de producción...${NC}"
    local changed=0
    if [[ -n "${OLD_AUTH_FAILURES:-}" ]]; then
        sed -i "s/max_auth_failures: [0-9]*/max_auth_failures: $OLD_AUTH_FAILURES/" $CONFIG && ((changed++)) || true
    fi
    if [[ -n "${OLD_MAX_MESSAGES:-}" ]]; then
        sed -i "s/max_messages: [0-9]*/max_messages: $OLD_MAX_MESSAGES/" $CONFIG && ((changed++)) || true
    fi
    if [[ -n "${OLD_MAX_UNIQUE_IPS:-}" ]]; then
        sed -i "s/max_unique_ips: [0-9]*/max_unique_ips: $OLD_MAX_UNIQUE_IPS/" $CONFIG && ((changed++)) || true
    fi
    if [[ -n "${OLD_MAX_IPS:-}" ]]; then
        sed -i "s/max_ips: [0-9]*/max_ips: $OLD_MAX_IPS/" $CONFIG && ((changed++)) || true
    fi
    if [[ -n "${OLD_MAX_RECIPIENTS:-}" ]]; then
        sed -i "s/max_recipients: [0-9]*/max_recipients: $OLD_MAX_RECIPIENTS/" $CONFIG && ((changed++)) || true
    fi
    if [[ -n "${OLD_MAX_BOUNCES:-}" ]]; then
        sed -i "s/max_bounces: [0-9]*/max_bounces: $OLD_MAX_BOUNCES/" $CONFIG && ((changed++)) || true
    fi
    if [[ -n "${OLD_QUEUE_THRESHOLD:-}" ]]; then
        sed -i "s/queue_threshold: [0-9]*/queue_threshold: $OLD_QUEUE_THRESHOLD/" $CONFIG && ((changed++)) || true
    fi
    systemctl restart sendguard-agent
    sleep 3
    if systemctl is-active --quiet sendguard-agent; then
        ok "Configuración de producción restaurada — agente reiniciado"
    else
        fail "Error al reiniciar el agente tras restaurar. Revisar: journalctl -u sendguard-agent -n 20"
    fi
}
trap restore_production EXIT

# Aplicar umbrales de prueba
sed -i 's/max_auth_failures: [0-9]*/max_auth_failures: 5/' $CONFIG
sed -i 's/max_messages: [0-9]*/max_messages: 3/'           $CONFIG
sed -i 's/max_unique_ips: [0-9]*/max_unique_ips: 3/'       $CONFIG
sed -i 's/max_ips: [0-9]*/max_ips: 3/'                     $CONFIG
sed -i 's/max_recipients: [0-9]*/max_recipients: 5/'       $CONFIG
sed -i 's/max_bounces: [0-9]*/max_bounces: 3/'             $CONFIG
sed -i 's/queue_threshold: [0-9]*/queue_threshold: 5/'     $CONFIG

info "Prueba: failures=5 messages=3 unique_ips=3 ips=3 recipients=5 bounces=3 queue=5"
info "Reiniciando agente con umbrales de prueba..."
systemctl restart sendguard-agent
sleep 5

if ! systemctl is-active --quiet sendguard-agent; then
    fail "El agente no arrancó tras aplicar umbrales de prueba."
    fail "Revisa: journalctl -u sendguard-agent -n 20"
    exit 1
fi
ok "Agente activo con umbrales de prueba"

# ─── Módulo 1: auth_failed ───────────────────────────────────────────────────
sep
echo -e "${BOLD}▶  1/9  auth_failed — brute-force desde una IP${NC}"
info "Inyectando 6 fallos SASL desde 203.0.113.10 (umbral: 5)"

mark_time
for i in {1..6}; do
    logger -p mail.warn -t "postfix/smtpd[10$i]" \
        "warning: unknown[203.0.113.10]: SASL LOGIN authentication failed: authentication failure"
done
sleep "$PAUSE"

if check_module "auth_failed"; then
    ok "auth_failed disparado — IP 203.0.113.10 bloqueada"
elif agent_log | grep -q '"ip":"203.0.113.10"'; then
    ok "auth_failed procesado (IP 203.0.113.10 encontrada en log)"
else
    warn "auth_failed no apareció en los logs del agente"
    info "Verificando que los logs llegan a mail.log..."
    if tail -20 /var/log/mail.log | grep -q "203.0.113.10"; then
        warn "Los logs SÍ llegan a mail.log — el módulo no disparó (¿umbral incorrecto?)"
        info "Umbral actual en config: $(_get max_auth_failures || echo 'no encontrado')"
    else
        warn "Los logs NO están en mail.log todavía — posible retraso de rsyslog"
        info "Espera 5s más y revisa: tail /var/log/mail.log | grep 203.0.113.10"
    fi
    dump_agent_log
fi

# ─── Módulo 2: sasl_connections (botnet) ─────────────────────────────────────
sep
echo -e "${BOLD}▶  2/9  sasl_connections — botnet con misma cuenta desde múltiples IPs${NC}"
info "Inyectando 3 auth exitosas de IPs distintas como admin@perulinux.pe (umbral: 3 IPs)"

mark_time
for i in 1 2 3; do
    logger -p mail.info -t "postfix/smtps/smtpd[20$i]" \
        "SC00000${i}A: client=unknown[10.10.$i.1], sasl_method=PLAIN, sasl_username=admin@perulinux.pe"
done
sleep "$PAUSE"

if check_module "sasl_connections"; then
    ok "sasl_connections disparado — cuenta suspendida + IPs bloqueadas"
else
    warn "sasl_connections no apareció en logs"
    dump_agent_log
fi

# ─── Módulo 3: dist_brute_force (credential stuffing distribuido) ─────────────
sep
echo -e "${BOLD}▶  3/9  dist_brute_force — credential stuffing distribuido${NC}"
info "Inyectando 3 fallos desde IPs distintas contra ceo@perulinux.pe (umbral: 3 IPs)"

mark_time
for i in 1 2 3; do
    logger -p mail.warn -t "postfix/smtpd[30$i]" \
        "warning: unknown[10.20.$i.1]: SASL LOGIN authentication failed: sasl_username=ceo@perulinux.pe"
done
sleep "$PAUSE"

if check_module "dist_brute_force"; then
    ok "dist_brute_force disparado — notificación enviada (sin bloqueo automático)"
else
    warn "dist_brute_force no apareció en logs"
    dump_agent_log
fi

# ─── Módulo 4: number_messages (volumen anómalo de envío) ────────────────────
sep
echo -e "${BOLD}▶  4/9  number_messages — cuenta enviando demasiados mensajes${NC}"
info "Inyectando 4 mensajes de bulk@perulinux.pe (umbral: 3)"

mark_time
for i in 1 2 3 4; do
    QID="NM${i}0001AA"
    logger -p mail.info -t "postfix/smtps/smtpd[40$i]" \
        "$QID: client=unknown[10.0.0.1], sasl_method=PLAIN, sasl_username=bulk@perulinux.pe"
    sleep 0.1
    logger -p mail.info -t "postfix/qmgr[4001]" \
        "$QID: from=<bulk@perulinux.pe>, size=2048, nrcpt=1 (queue active)"
done
sleep "$PAUSE"

if check_module "number_messages"; then
    ok "number_messages disparado — cuenta bulk@perulinux.pe suspendida"
else
    warn "number_messages no apareció en logs"
    dump_agent_log
fi

# ─── Módulo 5: rcpt_flood (spam masivo a múltiples destinatarios) ─────────────
# Usa IPs del rango TEST-NET-2 (RFC 5737, 198.51.100.0/24) para evitar que
# la IP de prueba coincida con la IP del propio servidor (que suele estar en
# la whitelist de sendguard) y provoque que los eventos se descarten silenciosamente.
sep
echo -e "${BOLD}▶  5/9  rcpt_flood — spam masivo a múltiples destinatarios${NC}"
info "Inyectando auth + 6 RCPT de flood@perulinux.pe desde 198.51.100.1 (umbral: 5)"

QID="RF00001BB"
mark_time
logger -p mail.info -t "postfix/smtps/smtpd[5001]" \
    "$QID: client=unknown[198.51.100.1], sasl_method=PLAIN, sasl_username=flood@perulinux.pe"
sleep 0.1
for i in {1..6}; do
    logger -p mail.info -t "postfix/smtps/smtpd[5001]" \
        "$QID: filter: RCPT from unknown[198.51.100.1]: <victim${i}@external.example>: FILTER smtp-amavis:[127.0.0.1]:10024"
done
sleep "$PAUSE"

if check_module "rcpt_flood"; then
    ok "rcpt_flood disparado — IP 198.51.100.1 bloqueada"
else
    warn "rcpt_flood no apareció en logs"
    dump_agent_log
fi

# ─── Módulo 6: domain_discovery (credential spray multi-dominio) ──────────────
sep
echo -e "${BOLD}▶  6/9  domain_discovery — credential spray contra múltiples dominios${NC}"
info "Inyectando 11 fallos desde 203.0.113.50 contra 11 dominios (umbral: 10)"

mark_time
for i in {1..11}; do
    logger -p mail.warn -t "postfix/smtpd[600]" \
        "warning: unknown[203.0.113.50]: SASL LOGIN authentication failed: sasl_username=admin@target${i}.com"
done
sleep "$PAUSE"

if check_module "domain_discovery"; then
    ok "domain_discovery disparado — IP 203.0.113.50 bloqueada"
else
    warn "domain_discovery no apareció en logs"
    dump_agent_log
fi

# ─── Módulo 7: bounce_rate ────────────────────────────────────────────────────
sep
echo -e "${BOLD}▶  7/9  bounce_rate — cuenta generando rebotes masivos${NC}"
info "Inyectando auth + qmgr + bounce × 4 de spammer@perulinux.pe (umbral: 3)"

mark_time
for i in 1 2 3 4; do
    QID="BN${i}0001CC"
    logger -p mail.info -t "postfix/smtps/smtpd[70$i]" \
        "$QID: client=unknown[10.0.0.1], sasl_method=PLAIN, sasl_username=spammer@perulinux.pe"
    sleep 0.1
    logger -p mail.info -t "postfix/qmgr[7001]" \
        "$QID: from=<spammer@perulinux.pe>, size=512, nrcpt=1 (queue active)"
    sleep 0.1
    logger -p mail.info -t "postfix/smtp[7002]" \
        "$QID: to=<bad${i}@notexist.com>, relay=notexist.com[9.9.9.9]:25, delay=1, delays=0.1/0/0.3/0.6, dsn=5.1.1, status=bounced (user unknown)"
done
sleep "$PAUSE"

if check_module "bounce_rate"; then
    ok "bounce_rate disparado — spammer@perulinux.pe suspendida"
else
    warn "bounce_rate no apareció en logs"
    dump_agent_log
fi

# ─── Módulo 8: queue_monitor ──────────────────────────────────────────────────
sep
echo -e "${BOLD}▶  8/9  queue_monitor — dominio destino rechazando mensajes${NC}"
info "Inyectando 6 deferrals hacia badrelay.com (umbral: 5)"

mark_time
for i in {1..6}; do
    logger -p mail.info -t "postfix/smtp[8001]" \
        "QM${i}0001DD: to=<user@badrelay.com>, relay=badrelay.com[1.2.3.4]:25, delay=1, delays=0.1/0/0.3/0.6, dsn=4.4.1, status=deferred (connection refused)"
done
sleep "$PAUSE"

if check_module "queue_monitor"; then
    ok "queue_monitor disparado — cola hacia badrelay.com purgada"
else
    warn "queue_monitor no apareció en logs"
    dump_agent_log
fi

# ─── Módulo 9: impossible_traveler ───────────────────────────────────────────
sep
echo -e "${BOLD}▶  9/9  impossible_traveler — login desde países distintos${NC}"
warn "Este módulo requiere tráfico real — no se puede simular con logger."
info "Condiciones:"
info "  1. GeoIP DB activa: /var/lib/GeoIP/GeoLite2-Country.mmdb"
info "  2. Mismo usuario autenticado desde 2 IPs de países distintos en < 30 min"
info "  3. Las IPs deben estar fuera de allowed_countries en agent.yaml"
info "  4. Se detecta vía /opt/zimbra/log/mailbox.log (protocolos imap/pop3/soap)"

GEOIP_PATH=$(grep 'db_path:' $CONFIG 2>/dev/null | awk '{print $2}' | head -1)
if [[ -f "${GEOIP_PATH:-/var/lib/GeoIP/GeoLite2-Country.mmdb}" ]]; then
    ok "GeoIP DB encontrada: ${GEOIP_PATH:-/var/lib/GeoIP/GeoLite2-Country.mmdb}"
else
    warn "GeoIP DB NO encontrada — usando API fallback (ipinfo.io)"
    info "Para instalar GeoIP local: revisar instrucciones en README.md"
fi

# ─── Resumen ──────────────────────────────────────────────────────────────────
sep
echo ""
echo -e "${BOLD}Validación completada: $(date '+%H:%M:%S')${NC}"
echo ""
echo "Comandos útiles:"
echo "  sendguard-ctl status"
echo "  journalctl -u sendguard-agent -n 100 -o cat --no-pager"
echo "  curl -s http://localhost:9099/blocked | python3 -m json.tool"
echo ""
echo "Alertas de Telegram/Email se envían para módulos con acción block/suspend."
echo ""
# (La restauración de umbrales ocurre automáticamente vía trap EXIT)
