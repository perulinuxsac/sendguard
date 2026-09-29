#!/bin/sh
# SendGuard — retiro de la integración SMTP heredada (v1.1.0)
#
# Desde v1.1.0 SendGuard NO interviene el SMTP del servidor de correo: la
# contención es solo por firewall (ipset/ufw) y suspensión de cuenta (zmprov).
# Este script deshace lo que versiones anteriores pedían configurar en Postfix:
#
#   - check_policy_service inet:<host>:9100         (sendguard-policyd)
#   - check_sender_access lmdb:.../sendguard_access  (rate-limit)
#
# y luego retira el servicio sendguard-policyd y el access file.
#
# ORDEN OBLIGATORIO: primero se quita el hook de Postfix y se verifica, y SOLO
# después se detiene policyd. Si Postfix sigue apuntando a un policy service que
# no responde, contesta 451 (temp-fail) a TODO el correo entrante. Ante cualquier
# duda (no se encuentra postconf, hook en master.cf, verificación fallida) el
# script falla SIN tocar policyd.
#
# También es el preinstall de los paquetes .deb/.rpm: si falla, el gestor de
# paquetes aborta la actualización y la versión anterior queda intacta.
#
# Idempotente: si no hay nada que retirar, no toca nada.
#
# Uso:  remove_smtp_hooks.sh            aplica los cambios
#       remove_smtp_hooks.sh --check    solo informa (no modifica nada)
#
# Entorno: SENDGUARD_CONFIG_DIR (default /etc/sendguard) para leer el puerto
#          del policyd de agent.yaml.
#
# Salida: imprime "CHANGED" si modificó algo (o, con --check, si hay algo que
# retirar). Código 0 = OK o nada que hacer; 1 = no se pudo retirar/verificar
# (policyd se deja intacto para no cortar correo).

set -u

CHECK=0
[ "${1:-}" = "--check" ] && CHECK=1

ZIMBRA_HOME="${SENDGUARD_ZIMBRA_HOME:-/opt/zimbra}"   # override solo para pruebas
TEMPLATE_DIR="$ZIMBRA_HOME/conf/zmconfigd"
AGENT_CONF="${SENDGUARD_CONFIG_DIR:-/etc/sendguard}/agent.yaml"
POLICYD_UNIT=/etc/systemd/system/sendguard-policyd.service
POLICYD_BIN=/usr/local/bin/sendguard-policyd
CHANGED=0
TS=$(date +%Y%m%d%H%M%S)

log()  { echo "[remove_smtp_hooks] $*"; }
fail() { echo "[remove_smtp_hooks] ERROR: $*" >&2; exit 1; }

# ── Puertos candidatos del policyd ───────────────────────────────────────────
# 9100 (default histórico) + el de agent.yaml + el que policyd escucha de verdad.
PORTS=9100
if [ -f "$AGENT_CONF" ]; then
    p=$(awk '/^policy_daemon:/{f=1;next} f&&/^[^ #]/{f=0} f&&/listen:/{gsub(/"/,"");n=split($2,a,":");print a[n];exit}' "$AGENT_CONF")
    case "$p" in ''|*[!0-9]*) ;; *) PORTS="$PORTS|$p" ;; esac
fi
if command -v ss >/dev/null 2>&1; then
    for p in $(ss -ltnp 2>/dev/null | awk '/"sendguard-polic/{n=split($4,a,":");print a[n]}'); do
        case "$p" in ''|*[!0-9]*) ;; *) PORTS="$PORTS|$p" ;; esac
    done
fi
PORTS=$(echo "$PORTS" | tr '|' '\n' | sort -un | paste -sd'|' -)

# Patrones (ERE). Postfix acepta coma o espacio como separador, y en master.cf
# (-o param=...) no puede haber espacios, así que el separador es [[:space:],]+.
# El puerto va seguido de un separador o fin de línea: 1003 no debe matchear
# el 10031 del cbpolicyd de Zimbra.
HOOK_CORE="(check_policy_service[[:space:],]+inet:[^[:space:],]*:($PORTS)|check_sender_access[[:space:],]+[a-z0-9]+:[^[:space:],]*sendguard_access)"
HOOK_RE="$HOOK_CORE([[:space:],]|\$)"

# ── Postfix: binarios de Zimbra (8.7+ o <=8.6) o del sistema ─────────────────
POSTCONF=""
CONF_DIR=""
POSTFIX_CMD=""
if [ -d "$ZIMBRA_HOME" ]; then
    for base in "$ZIMBRA_HOME/common" "$ZIMBRA_HOME/postfix"; do
        if [ -x "$base/sbin/postconf" ] && [ -d "$base/conf" ]; then
            POSTCONF="$base/sbin/postconf -c $base/conf"
            CONF_DIR="$base/conf"
            break
        fi
    done
    # Zimbra sin postconf localizable: no hay forma de verificar Postfix, y
    # retirar policyd a ciegas puede cortar el correo.
    [ -n "$POSTCONF" ] || fail "Zimbra detectado pero no se encontró postconf en $ZIMBRA_HOME/{common,postfix}/sbin"
    POSTFIX_CMD="su - zimbra -c"
elif command -v postconf >/dev/null 2>&1; then
    POSTCONF="postconf"
    CONF_DIR=$(postconf -h config_directory 2>/dev/null) || fail "postconf no responde"
    POSTFIX_CMD="sh -c"
fi

PARAMS="smtpd_client_restrictions smtpd_helo_restrictions smtpd_sender_restrictions
smtpd_relay_restrictions smtpd_recipient_restrictions smtpd_data_restrictions
smtpd_end_of_data_restrictions"

# strip_hooks: quita los hooks de una lista de restricciones Postfix sin tocar
# el resto de la línea.
strip_hooks() {
    echo "$1" | sed -E "s/$HOOK_CORE([[:space:],]+|\$)//g; s/[[:space:],]+\$//"
}

# require_postconf: si postconf no puede leer la configuración no se puede
# afirmar que esté limpia. Se llama en el shell principal (no en $(...),
# donde fail solo cerraría la subshell y se leería como "sin hooks").
require_postconf() {
    $POSTCONF -n >/dev/null 2>&1 || fail "postconf -n falló: no se puede leer la configuración de Postfix"
}

# main_cf_hooks: lista "param" con hooks en main.cf.
main_cf_hooks() {
    for p in $PARAMS; do
        $POSTCONF -h "$p" 2>/dev/null | grep -Eq "$HOOK_RE" && echo "$p"
    done
    return 0
}

# master_cf_hooks: líneas de master.cf (y su plantilla de Zimbra) con hooks
# en overrides -o. No se editan automáticamente: se pide revisión manual.
master_cf_hooks() {
    for f in "$CONF_DIR/master.cf" "$CONF_DIR/master.cf.in"; do
        [ -f "$f" ] && grep -nE "$HOOK_RE" "$f" | sed "s|^|$f:|"
    done
    return 0
}

postfix_running() {
    $POSTFIX_CMD 'postfix status' >/dev/null 2>&1
}

# ── 1. Plantillas de zmconfigd (persistencia en Zimbra) ─────────────────────
# Se editan ANTES que main.cf: si zmconfigd re-renderiza en medio, ya sale limpio.
if [ -d "$TEMPLATE_DIR" ]; then
    for f in "$TEMPLATE_DIR"/smtpd_*restrictions.cf; do
        [ -f "$f" ] || continue
        grep -Eq "^[[:space:]]*$HOOK_CORE[[:space:]]*\$" "$f" || continue
        log "hook de SendGuard en $f"
        CHANGED=1
        [ $CHECK -eq 1 ] && continue
        cp -p "$f" "$f.sendguard.bak.$TS" || fail "no se pudo respaldar $f"
        grep -Ev "^[[:space:]]*$HOOK_CORE[[:space:]]*\$" "$f.sendguard.bak.$TS" > "$f.tmp" \
            && cat "$f.tmp" > "$f" && rm -f "$f.tmp" \
            || fail "no se pudo editar $f"
        log "  retirado (respaldo: $f.sendguard.bak.$TS)"
    done
fi

# ── 2. Atributos LDAP de Zimbra ─────────────────────────────────────────────
# zmconfigd arma smtpd_client/data_restrictions directamente desde LDAP
# (zimbraMtaSmtpdClientRestrictions, zimbraMtaSmtpdDataRestrictions…): si el
# hook quedara ahí, reaparecería en main.cf en el próximo re-render. Se revisan
# TODOS los atributos (config global y servidor) en dos llamadas a zmprov.
if [ -x "$ZIMBRA_HOME/bin/zmprov" ]; then
    HOST=$(su - zimbra -c 'zmhostname' 2>/dev/null)
    for scope in gcf gs; do
        if [ "$scope" = gs ]; then
            [ -n "$HOST" ] || continue
            dump=$(su - zimbra -c "zmprov gs $HOST" 2>/dev/null) || fail "zmprov gs $HOST falló"
            mod="ms $HOST"
        else
            dump=$(su - zimbra -c "zmprov gacf" 2>/dev/null) || fail "zmprov gacf falló"
            mod="mcf"
        fi
        hits=$(echo "$dump" | grep -E "^zimbra[A-Za-z]+: .*$HOOK_RE")
        [ -n "$hits" ] || continue
        CHANGED=1
        echo "$hits" | while IFS= read -r line; do
            attr=${line%%: *}
            v=${line#*: }
            log "hook de SendGuard en LDAP ($mod $attr): $v"
            [ $CHECK -eq 1 ] && continue
            case "$v" in *\'*) fail "valor LDAP con comilla simple, retirar a mano: $attr" ;; esac
            su - zimbra -c "zmprov $mod -$attr '$v'" || fail "zmprov $mod -$attr falló"
            log "  retirado de LDAP"
        done || exit 1
    done
fi

# ── 3. Configuración viva de Postfix (main.cf / master.cf) ──────────────────
if [ -n "$POSTCONF" ]; then
    require_postconf
    MASTER_HITS=$(master_cf_hooks)
    if [ -n "$MASTER_HITS" ]; then
        echo "$MASTER_HITS" | while IFS= read -r l; do log "hook en master.cf: $l"; done
        fail "hay hooks de SendGuard en overrides de master.cf: retíralos a mano (y de master.cf.in en Zimbra) y reintenta. policyd NO se toca."
    fi

    HOOKED=$(main_cf_hooks)
    if [ -n "$HOOKED" ]; then
        CHANGED=1
        for p in $HOOKED; do
            cur=$($POSTCONF -h "$p")
            new=$(strip_hooks "$cur")
            log "$p:"
            log "  antes:   $cur"
            log "  después: $new"
            [ $CHECK -eq 1 ] && continue
            $POSTCONF -e "$p = $new" || fail "postconf -e $p falló"
        done
        if [ $CHECK -eq 0 ]; then
            # Con Postfix detenido basta el cambio en main.cf: lo toma al arrancar.
            if postfix_running; then
                $POSTFIX_CMD 'postfix reload' >/dev/null 2>&1 || fail "postfix reload falló"
                log "postfix recargado"
            else
                log "postfix no está corriendo: el cambio se aplicará al arrancar"
            fi
        fi
    fi

    # Verificación final (también en --check: si no se puede leer, falla).
    if [ $CHECK -eq 0 ] && { require_postconf; [ -n "$(main_cf_hooks)" ]; }; then
        fail "Postfix sigue referenciando SendGuard tras el cambio; policyd NO se detiene. Revisa 'postconf -n'."
    fi
fi

# ── 4. sendguard-policyd ────────────────────────────────────────────────────
POLICYD_PRESENT=0
if [ -f "$POLICYD_UNIT" ] || [ -f "$POLICYD_BIN" ] || \
   systemctl is-active --quiet sendguard-policyd 2>/dev/null; then
    POLICYD_PRESENT=1
fi

if [ $CHECK -eq 1 ]; then
    [ $POLICYD_PRESENT -eq 1 ] && { log "sendguard-policyd presente"; CHANGED=1; }
    [ $CHANGED -eq 1 ] && echo "CHANGED (check: no se modificó nada)"
    exit 0
fi

# Solo se llega aquí con Postfix verificado sin hooks.
if [ $POLICYD_PRESENT -eq 1 ]; then
    systemctl disable --now sendguard-policyd.service >/dev/null 2>&1 || true
    rm -f "$POLICYD_UNIT" "$POLICYD_BIN"
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl reset-failed sendguard-policyd.service >/dev/null 2>&1 || true
    log "sendguard-policyd detenido y retirado"
    CHANGED=1
fi

# ── 5. Access file del rate-limit (sin referencias en main.cf ni master.cf) ──
if [ -n "$CONF_DIR" ]; then
    for f in "$CONF_DIR/sendguard_access" "$CONF_DIR/sendguard_access.lmdb" "$CONF_DIR/sendguard_access.db"; do
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
