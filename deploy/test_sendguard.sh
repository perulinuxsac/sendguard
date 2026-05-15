#!/bin/bash
# SendGuard — Script de validación integral de todos los módulos de detección.
# Ejecutar DESPUÉS de desplegar el binario y reiniciar el servicio.
#
# Uso:
#   bash /opt/sendguard/test_sendguard.sh
#
# Monitorear en paralelo (terminal aparte):
#   journalctl -u sendguard-agent -f -o cat
#
# Notas:
#   - Las cuentas usadas (bulk@, flood@, etc.) no necesitan existir en Zimbra;
#     el error "account not found" en los logs es ESPERADO para cuentas de prueba.
#   - Los umbrales bajos en agent.yaml (max_messages: 3, max_recipients: 5, etc.)
#     son los de PRUEBA. Restaurar a producción tras validar.
#   - Para ver alertas en tiempo real: journalctl -u sendguard-agent -f -o cat

set -euo pipefail

AGENT_LOG="journalctl -u sendguard-agent -n 100 -o cat --no-pager"
PAUSE=4   # segundos entre pruebas para que el engine procese los eventos

ok()   { echo "  ✓ $*"; }
warn() { echo "  ⚠ $*"; }
info() { echo "  → $*"; }
sep()  { echo ""; echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"; }

# ─── Pre-flight ──────────────────────────────────────────────────────────────

sep
echo "SendGuard — Validación integral de módulos"
echo "$(date '+%Y-%m-%d %H:%M:%S')"
sep

if ! systemctl is-active --quiet sendguard-agent; then
    echo "ERROR: sendguard-agent no está corriendo. Inícialo primero."
    exit 1
fi
ok "sendguard-agent activo"

VERSION=$(journalctl -u sendguard-agent -n 50 --no-pager -o cat 2>/dev/null | \
    grep '"msg":"sendguard agent iniciando"' | tail -1 | \
    grep -oP '"version":"\K[^"]+' || echo "desconocida")
ok "versión en log: $VERSION"
echo ""

# ─── Módulo 1: auth_failed ───────────────────────────────────────────────────
# 6 fallos desde la misma IP → bloquear IP (umbral: 5 en 300s)

sep
echo "▶  1/9  auth_failed — fuerza bruta desde una IP"
info "Inyectando 6 fallos SASL desde 203.0.113.10 (umbral: 5)"

for i in {1..6}; do
  logger -p mail.warn -t "postfix/smtpd[10$i]" \
    "warning: unknown[203.0.113.10]: SASL LOGIN authentication failed: authentication failure"
done
sleep "$PAUSE"

if $AGENT_LOG | grep -q '"ip":"203.0.113.10"'; then
    ok "IP 203.0.113.10 procesada — revisa Telegram para confirmar bloqueo"
else
    warn "No se encontró log de 203.0.113.10 — verifica que mail.log sea la fuente correcta"
fi

# ─── Módulo 2: sasl_connections (botnet por IPs únicas) ─────────────────────
# 3 IPs distintas autenticando como la misma cuenta → suspender + bloquear todas

sep
echo "▶  2/9  sasl_connections — botnet con misma cuenta desde múltiples IPs"
info "Inyectando 3 auth exitosas de IPs distintas como admin@perulinux.pe (umbral: 3)"

for i in 1 2 3; do
  logger -p mail.info -t "postfix/smtps/smtpd[20$i]" \
    "SC00000${i}A: client=unknown[10.10.$i.1], sasl_method=PLAIN, sasl_username=admin@perulinux.pe"
done
sleep "$PAUSE"

if $AGENT_LOG | grep -q '"module":"sasl_connections"'; then
    ok "sasl_connections disparado — cuenta suspendida + IPs bloqueadas"
else
    warn "sasl_connections no aparece en logs — verifica max_unique_ips en config"
fi

# ─── Módulo 3: dist_brute_force (credential stuffing) ───────────────────────
# 3 IPs distintas fallando contra la misma cuenta → notificar (sin bloqueo)

sep
echo "▶  3/9  dist_brute_force — credential stuffing distribuido"
info "Inyectando 3 fallos desde IPs distintas contra ceo@perulinux.pe (umbral: 3)"

for i in 1 2 3; do
  logger -p mail.warn -t "postfix/smtpd[30$i]" \
    "warning: unknown[10.20.$i.1]: SASL LOGIN authentication failed: sasl_username=ceo@perulinux.pe"
done
sleep "$PAUSE"

if $AGENT_LOG | grep -q '"module":"dist_brute_force"'; then
    ok "dist_brute_force disparado — notificación enviada (sin bloqueo automático)"
else
    warn "dist_brute_force no aparece — verifica max_ips y que los logs incluyan sasl_username="
fi

# ─── Módulo 4: number_messages (volumen anómalo de envío) ───────────────────
# 4 mensajes desde la misma cuenta en ventana → suspender cuenta

sep
echo "▶  4/9  number_messages — cuenta enviando demasiados mensajes"
info "Inyectando 4 mensajes de bulk@perulinux.pe (umbral: 3)"

for i in 1 2 3 4; do
  QID="NM${i}0001AA"
  logger -p mail.info -t "postfix/smtps/smtpd[40$i]" \
    "$QID: client=unknown[10.0.0.1], sasl_method=PLAIN, sasl_username=bulk@perulinux.pe"
  sleep 0.1
  logger -p mail.info -t "postfix/qmgr[4001]" \
    "$QID: from=<bulk@perulinux.pe>, size=2048, nrcpt=1 (queue active)"
done
sleep "$PAUSE"

if $AGENT_LOG | grep -q '"module":"number_messages"'; then
    ok "number_messages disparado — cuenta bulk@perulinux.pe suspendida"
else
    warn "number_messages no aparece — verifica max_messages en config (¿aún en 3?)"
fi

# ─── Módulo 5: rcpt_flood (destinatarios masivos) ────────────────────────────
# 6 RCPT TO desde IP autenticada → bloquear IP + suspender cuenta

sep
echo "▶  5/9  rcpt_flood — spam masivo a múltiples destinatarios"
info "Inyectando auth + 6 RCPT de flood@perulinux.pe desde 10.30.0.1 (umbral: 5)"

QID="RF00001BB"
logger -p mail.info -t "postfix/smtps/smtpd[5001]" \
  "$QID: client=unknown[10.30.0.1], sasl_method=PLAIN, sasl_username=flood@perulinux.pe"
sleep 0.1
for i in {1..6}; do
  logger -p mail.info -t "postfix/smtps/smtpd[5001]" \
    "$QID: filter: RCPT from unknown[10.30.0.1]: <flood@perulinux.pe>: FILTER smtp-amavis:[127.0.0.1]:10024"
done
sleep "$PAUSE"

if $AGENT_LOG | grep -q '"module":"rcpt_flood"'; then
    ok "rcpt_flood disparado — IP 10.30.0.1 bloqueada + flood@perulinux.pe suspendida"
else
    warn "rcpt_flood no aparece — verifica max_recipients (¿en 5?) y que filter: RCPT esté configurado"
fi

# ─── Módulo 6: domain_discovery (credential spray multi-dominio) ─────────────
# 11 dominios distintos atacados desde la misma IP → bloquear IP

sep
echo "▶  6/9  domain_discovery — credential spray contra múltiples dominios"
info "Inyectando 11 fallos desde 203.0.113.50 contra 11 dominios distintos (umbral: 10)"

for i in {1..11}; do
  logger -p mail.warn -t "postfix/smtpd[600]" \
    "warning: unknown[203.0.113.50]: SASL LOGIN authentication failed: sasl_username=admin@target${i}.com"
done
sleep "$PAUSE"

if $AGENT_LOG | grep -q '"module":"domain_discovery"'; then
    ok "domain_discovery disparado — IP 203.0.113.50 bloqueada"
else
    warn "domain_discovery no aparece — verifica max_domains (¿en 10?) y que los fallos incluyan sasl_username="
fi

# ─── Módulo 7: bounce_rate (rebotes por cuenta comprometida) ─────────────────
# Cuenta que genera muchos bounces → suspender
# Requiere: max_bounces: 3 en agent.yaml para esta prueba (default: 50)

sep
echo "▶  7/9  bounce_rate — cuenta generando rebotes masivos"

BOUNCE_THRESHOLD=$(grep 'max_bounces:' /etc/sendguard/agent.yaml 2>/dev/null | awk '{print $2}' | head -1)
if [ "${BOUNCE_THRESHOLD:-50}" -gt 5 ]; then
    warn "max_bounces = ${BOUNCE_THRESHOLD:-50}. Para probar este módulo reduce a 3 en agent.yaml:"
    warn "  sed -i 's/max_bounces: [0-9]*/max_bounces: 3/' /etc/sendguard/agent.yaml"
    warn "  systemctl restart sendguard-agent"
    warn "  Luego vuelve a ejecutar solo este bloque."
else
    info "Inyectando auth + qmgr + bounce × 4 de spammer@perulinux.pe (umbral: $BOUNCE_THRESHOLD)"
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
    if $AGENT_LOG | grep -q '"module":"bounce_rate"'; then
        ok "bounce_rate disparado — spammer@perulinux.pe suspendida"
    else
        warn "bounce_rate no apareció — revisa los logs completos"
    fi
fi

# ─── Módulo 8: queue_monitor (deferrals al mismo dominio) ────────────────────
# N deferrals hacia el mismo dominio destino → purgar cola
# Requiere: queue_threshold: 5 (default: 2500 — demasiado alto para prueba manual)

sep
echo "▶  8/9  queue_monitor — dominio destino rechazando mensajes"

QUEUE_THRESHOLD=$(grep 'queue_threshold:' /etc/sendguard/agent.yaml 2>/dev/null | awk '{print $2}' | head -1)
if [ "${QUEUE_THRESHOLD:-2500}" -gt 10 ]; then
    warn "queue_threshold = ${QUEUE_THRESHOLD:-2500}. Para probar reduce a 5 en agent.yaml:"
    warn "  sed -i 's/queue_threshold: [0-9]*/queue_threshold: 5/' /etc/sendguard/agent.yaml"
    warn "  systemctl restart sendguard-agent"
    warn "  Luego inyectar 6 deferrals:"
    for i in {1..6}; do
      echo "    logger -p mail.info -t 'postfix/smtp[8001]' \\"
      echo "      \"QM${i}0001DD: to=<user@badrelay.com>, relay=badrelay.com[1.2.3.4]:25, delay=1, delays=0.1/0/0.3/0.6, dsn=4.4.1, status=deferred (connection refused)\""
    done
else
    info "Inyectando 6 deferrals hacia badrelay.com (umbral: $QUEUE_THRESHOLD)"
    for i in {1..6}; do
      logger -p mail.info -t "postfix/smtp[8001]" \
        "QM${i}0001DD: to=<user@badrelay.com>, relay=badrelay.com[1.2.3.4]:25, delay=1, delays=0.1/0/0.3/0.6, dsn=4.4.1, status=deferred (connection refused)"
    done
    sleep "$PAUSE"
    if $AGENT_LOG | grep -q '"module":"queue_monitor"'; then
        ok "queue_monitor disparado — cola hacia badrelay.com purgada"
    else
        warn "queue_monitor no apareció — revisa los logs"
    fi
fi

# ─── Módulo 9: impossible_traveler ───────────────────────────────────────────
# Login desde países distintos en < 30 min → notificar

sep
echo "▶  9/9  impossible_traveler — login desde países distintos"
warn "Este módulo se activa con tráfico real — no se puede simular fácilmente con logger."
warn "Requiere:"
warn "  1. GeoIP DB configurada: db_path: /var/lib/GeoIP/GeoLite2-Country.mmdb"
warn "  2. Dos logins reales del mismo usuario desde IPs de países distintos en < 30 min"
warn "  3. Ambos IPs deben estar fuera de allowed_countries en agent.yaml"
info "Se monitorea automáticamente en mailbox.log (imap/pop3/soap/account protocols)"

# ─── Estado final ────────────────────────────────────────────────────────────

sep
echo ""
echo "Validación completada: $(date '+%H:%M:%S')"
echo ""
echo "Revisa:"
echo "  • journalctl -u sendguard-agent -n 100 -o cat --no-pager"
echo "  • Alertas en Telegram"
echo "  • sendguard-ctl status    (si sendguard-ctl está instalado)"
echo ""
echo "Umbrales de PRUEBA activos — restaurar a producción:"
echo "  max_messages: 300   max_recipients: 50   max_unique_ips: 5"
echo "  max_ips: 5          max_bounces: 50       queue_threshold: 2500"
echo ""
echo "  sed -i 's/max_messages: [0-9]*/max_messages: 300/' /etc/sendguard/agent.yaml"
echo "  sed -i 's/max_recipients: [0-9]*/max_recipients: 50/' /etc/sendguard/agent.yaml"
echo "  sed -i 's/max_unique_ips: [0-9]*/max_unique_ips: 5/' /etc/sendguard/agent.yaml"
echo "  sed -i 's/max_ips: [0-9]*/max_ips: 5/' /etc/sendguard/agent.yaml"
echo "  systemctl restart sendguard-agent"
sep
