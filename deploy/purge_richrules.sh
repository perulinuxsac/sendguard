#!/bin/bash
# purge_richrules.sh — migración a firewalld-ipset: elimina las rich rules de
# bloqueo acumuladas por SendGuard (una por IP baneada) de la configuración
# permanente de firewalld y recarga.
#
# Elimina SOLO reglas con el patrón exacto que generaba SendGuard:
#   <rule family="ipv4">
#     <source address="X.X.X.X[/nn]"/>
#     <reject/>
#   </rule>
# Cualquier regla con más atributos (puertos, servicios, log, limit...) se
# conserva intacta. Se hace backup del XML antes de tocarlo.
#
# Ejecutar DESPUÉS de desplegar SendGuard >= v1.0.10 (backend firewalld-ipset):
# al recargar firewalld se pierden las entradas runtime del ipset, por lo que
# el script reinicia el agente al final para que repueble el set desde SQLite.
set -euo pipefail

if ! command -v firewall-cmd >/dev/null 2>&1; then
    echo "firewalld no presente en este host; nada que purgar." >&2
    exit 0
fi

ZONE=$(firewall-cmd --get-default-zone)
XML="/etc/firewalld/zones/${ZONE}.xml"

if [ ! -f "$XML" ]; then
    echo "No existe $XML; no hay reglas permanentes que purgar."
    exit 0
fi

BACKUP="${XML}.pre-ipset-$(date +%Y%m%d%H%M%S)"
cp -a "$XML" "$BACKUP"
echo "Backup: $BACKUP"

BEFORE=$(grep -c '<rule ' "$XML" || true)

awk '
/<rule family="ipv4">/ { buf = $0; inrule = 1; next }
inrule {
    buf = buf "\n" $0
    if (/<\/rule>/) {
        # Regla SendGuard: solo source address + reject, nada más.
        if (buf ~ /<source address="[0-9.\/]+"\/>/ && buf ~ /<reject\/>/ &&
            buf !~ /port|service|protocol|log|limit|accept|drop|mark|masquerade|forward|icmp/) {
            # descartar
        } else {
            print buf
        }
        inrule = 0; buf = ""
    }
    next
}
{ print }
' "$XML" > "${XML}.tmp"
mv "${XML}.tmp" "$XML"
restorecon "$XML" 2>/dev/null || true

AFTER=$(grep -c '<rule ' "$XML" || true)
echo "Reglas rich permanentes: ${BEFORE} → ${AFTER} (eliminadas: $((BEFORE - AFTER)))"

echo "Recargando firewalld (puede tardar)..."
time firewall-cmd --reload

echo "Reglas rich activas tras reload: $(firewall-cmd --list-rich-rules | wc -l)"

# Repoblar el ipset desde SQLite (el reload vació las entradas runtime).
systemctl restart sendguard-agent
sleep 3
echo "Entradas en el ipset sendguard: $(firewall-cmd --ipset=sendguard --get-entries 2>/dev/null | wc -w)"
echo "OK"
