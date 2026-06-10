#!/bin/sh
# SendGuard — post-remove (.deb/.rpm)
# Recarga systemd tras quitar las units. No borra /etc/sendguard ni
# /var/lib/sendguard (config y base de datos del cliente se conservan).
set -e

systemctl daemon-reload >/dev/null 2>&1 || true

exit 0
