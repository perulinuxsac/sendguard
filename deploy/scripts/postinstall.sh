#!/bin/sh
# SendGuard — post-install (.deb/.rpm)
# Recarga systemd, habilita el servicio y lo reinicia SOLO si ya hay config.
# En instalación nueva no arranca: el agente requiere /etc/sendguard/agent.yaml,
# que genera Ansible o install.sh.
set -e

# Los hooks SMTP de versiones <1.1.0 los retira el preinstall
# (remove_smtp_hooks.sh), antes de reemplazar archivos: si llegamos aquí,
# Postfix ya no referencia a SendGuard.

systemctl daemon-reload || true

# Habilitar para que persista tras configurarse (no lo arranca todavía).
systemctl enable sendguard-agent.service >/dev/null 2>&1 || true

if [ -f /etc/sendguard/agent.yaml ]; then
    # Upgrade o reinstalación sobre un host ya configurado: aplicar binarios nuevos.
    systemctl restart sendguard-agent.service || true
    echo "SendGuard actualizado y servicio reiniciado."
else
    cat <<'MSG'
SendGuard instalado.
Falta la configuración del cliente. Pasos:
  1. Copia el ejemplo:   cp /etc/sendguard/agent.yaml.example /etc/sendguard/agent.yaml
  2. Edítalo (server_id, client_name, países, etc.) o despliega con Ansible.
  3. Arranca:            systemctl enable --now sendguard-agent
MSG
fi

exit 0
