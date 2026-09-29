#!/bin/sh
# SendGuard — retiro de la integración SMTP heredada (v1.1.0)
#
# Desde v1.1.0 SendGuard NO interviene el SMTP del servidor de correo: la
# contención es solo por firewall (ipset/ufw) y suspensión de cuenta (zmprov).
# Este script deshace lo que versiones anteriores pedían configurar en Postfix:
#
#   - check_policy_service inet:127.0.0.1:9100   (sendguard-policyd)
#   - check_sender_access lmdb:.../sendguard_access   (rate-limit)
#
# y luego retira el servicio sendguard-policyd.
#
# ORDEN OBLIGATORIO: primero se quita el hook de Postfix y se verifica, y SOLO
# después se detiene policyd. Si Postfix sigue apuntando a un policy service que
# no responde, contesta 451 (temp-fail) a TODO el correo entrante.
#
# Idempotente: si no hay nada que retirar, no toca nada.
#
# Uso:  remove_smtp_hooks.sh            aplica los cambios
#       remove_smtp_hooks.sh --check    solo informa (no modifica nada)
#
# Salida: imprime "CHANGED" si modificó algo. Código 0 = OK (o nada que hacer),
# 1 = no se pudo retirar el hook (policyd se deja corriendo para no cortar correo).

set -u

CHECK=0
[ "${1:-}" = "--check" ] && CHECK=1

ZIMBRA_HOME=/opt/zimbra
TEMPLATE_DIR="$ZIMBRA_HOME/conf/zmconfigd"
AGENT_CONF=/etc/sendguard/agent.yaml
CHANGED=0
TS=$(date +%Y%m%d%H%M%S)

log()  { echo "[remove_smtp_hooks] $*"; }
fail() { echo "[remove_smtp_hooks] ERROR: $*" >&2; exit 1; }

# Puerto del policyd: el configurado en agent.yaml o el default 9100.
PORT=9100
if [ -f "$AGENT_CONF" ]; then
    p=$(awk '/^policy_daemon:/{f=1;next} f&&/^[^ #]/{f=0} f&&/listen:/{gsub(/"/,"");n=split($2,a,":");print a[n];exit}' "$AGENT_CONF")
    case "$p" in ''|*[!0-9]*) ;; *) PORT=$p ;; esac
fi

# Regex (ERE) de los hooks de SendGuard, como tokens de una restricción Postfix.
POLICY_RE="check_policy_service[[:space:]]+inet:(127\\.0\\.0\\.1|localhost):$PORT"
ACCESS_RE="check_sender_access[[:space:]]+[a-z]+:[^[:space:],]*sendguard_access"
HOOK_RE="($POLICY_RE|$ACCESS_RE)"

# ── Postfix: binarios de Zimbra o del sistema ────────────────────────────────
if [ -x "$ZIMBRA_HOME/common/sbin/postconf" ]; then
    POSTCONF="$ZIMBRA_HOME/common/sbin/postconf -c $ZIMBRA_HOME/common/conf"
    ACCESS_DIR="$ZIMBRA_HOME/common/conf"
    RELOAD="su - zimbra -c 'postfix reload'"
elif command -v postconf >/dev/null 2>&1; then
    POSTCONF="postconf"
    ACCESS_DIR=$(postconf -h config_directory 2>/dev/null || echo /etc/postfix)
    RELOAD="postfix reload"
else
    POSTCONF=""
    ACCESS_DIR=""
fi

PARAMS="smtpd_client_restrictions smtpd_helo_restrictions smtpd_sender_restrictions
smtpd_relay_restrictions smtpd_recipient_restrictions smtpd_data_restrictions
smtpd_end_of_data_restrictions"

# strip_hooks: quita los hooks de una lista de restricciones Postfix sin tocar
# el resto de la línea (comas y espacios son separadores equivalentes en Postfix).
strip_hooks() {
    echo "$1" | sed -E "s/$POLICY_RE[[:space:],]*//g; s/$ACCESS_RE[[:space:],]*//g; s/[[:space:],]+$//"
}

live_has_hooks() {
    [ -n "$POSTCONF" ] || return 1
    for p in $PARAMS; do
        $POSTCONF -h "$p" 2>/dev/null | grep -Eq "$HOOK_RE" && return 0
    done
    return 1
}

# ── 1. Plantillas de zmconfigd (persistencia en Zimbra) ─────────────────────
# Se editan ANTES que main.cf: si zmconfigd re-renderiza en medio, ya sale limpio.
if [ -d "$TEMPLATE_DIR" ]; then
    for f in "$TEMPLATE_DIR"/smtpd_*restrictions.cf; do
        [ -f "$f" ] || continue
        grep -Eq "^[[:space:]]*$HOOK_RE[[:space:]]*$" "$f" || continue
        log "hook de SendGuard en $f"
        CHANGED=1
        [ $CHECK -eq 1 ] && continue
        cp -p "$f" "$f.sendguard.bak.$TS" || fail "no se pudo respaldar $f"
        grep -Ev "^[[:space:]]*$HOOK_RE[[:space:]]*$" "$f.sendguard.bak.$TS" > "$f.tmp" \
            && cat "$f.tmp" > "$f" && rm -f "$f.tmp" \
            || fail "no se pudo editar $f"
        log "  retirado (respaldo: $f.sendguard.bak.$TS)"
    done
fi

# ── 2. Atributos LDAP de Zimbra (si alguien usó zmprov mcf/ms) ───────────────
ZMPROV="$ZIMBRA_HOME/bin/zmprov"
if [ -x "$ZMPROV" ]; then
    HOST=$(su - zimbra -c 'zmhostname' 2>/dev/null)
    for attr in zimbraMtaRestriction zimbraMtaSmtpdSenderRestrictions; do
        for scope in gcf gs; do
            if [ "$scope" = gs ]; then
                [ -n "$HOST" ] || continue
                vals=$(su - zimbra -c "zmprov gs $HOST $attr" 2>/dev/null | sed -n "s/^$attr: //p")
                mod="ms $HOST"
            else
                vals=$(su - zimbra -c "zmprov gcf $attr" 2>/dev/null | sed -n "s/^$attr: //p")
                mod="mcf"
            fi
            echo "$vals" | grep -E "$HOOK_RE" | while IFS= read -r v; do
                log "hook de SendGuard en LDAP ($scope $attr): $v"
                [ $CHECK -eq 1 ] && continue
                su - zimbra -c "zmprov $mod -$attr '$v'" || fail "zmprov $mod -$attr falló"
                log "  retirado de LDAP"
            done || exit 1
            echo "$vals" | grep -Eq "$HOOK_RE" && CHANGED=1
        done
    done
fi

# ── 3. Configuración viva de Postfix (main.cf) ──────────────────────────────
if live_has_hooks; then
    CHANGED=1
    for p in $PARAMS; do
        cur=$($POSTCONF -h "$p" 2>/dev/null) || continue
        echo "$cur" | grep -Eq "$HOOK_RE" || continue
        new=$(strip_hooks "$cur")
        log "$p:"
        log "  antes:   $cur"
        log "  después: $new"
        [ $CHECK -eq 1 ] && continue
        $POSTCONF -e "$p = $new" || fail "postconf -e $p falló"
    done
    if [ $CHECK -eq 0 ]; then
        sh -c "$RELOAD" >/dev/null 2>&1 || fail "postfix reload falló"
        log "postfix recargado"
        if live_has_hooks; then
            fail "Postfix sigue referenciando SendGuard tras el cambio; policyd NO se detiene. Revisa 'postconf -n'."
        fi
    fi
fi

# En --check no se sigue: retirar policyd sin haber quitado el hook cortaría correo.
if [ $CHECK -eq 1 ]; then
    [ $CHANGED -eq 1 ] && echo "CHANGED (check: no se modificó nada)"
    exit 0
fi

# ── 4. Retirar sendguard-policyd (solo ahora que Postfix ya no lo usa) ───────
if [ -f /etc/systemd/system/sendguard-policyd.service ] || \
   systemctl is-active --quiet sendguard-policyd 2>/dev/null || \
   [ -f /usr/local/bin/sendguard-policyd ]; then
    systemctl disable --now sendguard-policyd.service >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/sendguard-policyd.service /usr/local/bin/sendguard-policyd
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl reset-failed sendguard-policyd.service >/dev/null 2>&1 || true
    log "sendguard-policyd detenido y retirado"
    CHANGED=1
fi

# ── 5. Access file del rate-limit (ya sin referencias en Postfix) ───────────
if [ -n "$ACCESS_DIR" ]; then
    for f in "$ACCESS_DIR/sendguard_access" "$ACCESS_DIR/sendguard_access.lmdb" "$ACCESS_DIR/sendguard_access.db"; do
        [ -e "$f" ] || continue
        rm -f "$f" && log "eliminado $f"
        CHANGED=1
    done
fi

if [ $CHANGED -eq 1 ]; then
    echo "CHANGED"
else
    log "nada que retirar: SendGuard no tiene hooks en Postfix"
fi
exit 0
