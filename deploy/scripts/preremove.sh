#!/bin/sh
# SendGuard — pre-remove (.deb/.rpm)
# Detiene y deshabilita los servicios SOLO en desinstalación definitiva,
# no durante un upgrade.
#   deb:  $1 = "remove" (desinstala) | "upgrade"
#   rpm:  $1 = "0" (desinstala)      | "1" (upgrade)
set -e

if [ "$1" = "remove" ] || [ "$1" = "0" ] || [ "$1" = "purge" ]; then
    systemctl disable --now sendguard-agent.service sendguard-policyd.service >/dev/null 2>&1 || true
fi

exit 0
