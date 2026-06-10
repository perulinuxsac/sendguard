#!/bin/sh
# SendGuard — post-install (.deb/.rpm)
# Recarga systemd, habilita los servicios y los reinicia SOLO si ya hay config.
# En instalación nueva no arranca: el agente requiere /etc/sendguard/agent.yaml,
# que genera Ansible o install.sh.
set -e

systemctl daemon-reload || true

# Habilitar para que persistan tras configurarse (no los arranca todavía).
systemctl enable sendguard-agent.service sendguard-policyd.service >/dev/null 2>&1 || true

if [ -f /etc/sendguard/agent.yaml ]; then
    # Upgrade o reinstalación sobre un host ya configurado: aplicar binarios nuevos.
    systemctl restart sendguard-agent.service sendguard-policyd.service || true
    echo "SendGuard actualizado y servicios reiniciados."
else
    cat <<'MSG'
SendGuard instalado.
Falta la configuración del cliente. Pasos:
  1. Copia el ejemplo:   cp /etc/sendguard/agent.yaml.example /etc/sendguard/agent.yaml
  2. Edítalo (server_id, client_name, países, etc.) o despliega con Ansible.
  3. Arranca:            systemctl enable --now sendguard-agent sendguard-policyd
MSG
fi

exit 0
