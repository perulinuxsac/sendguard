# Despliegue de SendGuard con Ansible

Rol idempotente para instalar/actualizar el agente SendGuard en una flota de
servidores **Zimbra** (Rocky/RHEL con firewalld o Ubuntu/Debian con ufw).

Hace lo mismo que `deploy/install.sh` pero desatendido y repetible: copia los
binarios, descarga la DB GeoIP MaxMind (+ cron de actualización), genera
`/etc/sendguard/agent.yaml`, instala los servicios systemd `sendguard-agent` y
`sendguard-policyd`, y los habilita y arranca.

## Requisitos

- Ansible 2.12+ en el control node.
- Acceso SSH (root o usuario con sudo) a cada host.
- Cada host es un servidor Zimbra con firewall activo (firewalld o ufw).
- Binarios compilados en `dist/` del repo: ejecuta en la raíz del repo

  ```bash
  make package      # compila agent, ctl y policyd → dist/
  ```

## Estructura

```
deploy/ansible/
├── ansible.cfg
├── site.yml                      # playbook principal
├── inventory.example.ini         # → copia a inventory.ini
├── group_vars/all.example.yml    # → copia a group_vars/all.yml (CIFRAR)
├── host_vars/*.example.yml       # → uno por host con lo específico
└── roles/sendguard/              # el rol (autodetecta OS/firewall/rutas Zimbra)
```

## Puesta en marcha

1. **Compila los binarios** (una sola vez por release):

   ```bash
   cd <raíz-del-repo> && make package
   ```

2. **Inventario** — copia y edita:

   ```bash
   cd deploy/ansible
   cp inventory.example.ini inventory.ini
   $EDITOR inventory.ini
   ```

3. **Variables compartidas** — copia, rellena tus credenciales y **cífralas**:

   ```bash
   cp group_vars/all.example.yml group_vars/all.yml
   $EDITOR group_vars/all.yml
   ansible-vault encrypt group_vars/all.yml
   ```

4. **Variables por host** (whitelist, server_id, cliente si difiere) — crea
   `host_vars/<nombre-de-inventario>.yml` según el ejemplo. Es opcional: sin él,
   `server_id` = nombre de inventario y se usan los valores compartidos.

5. **Prueba en seco** (no cambia nada):

   ```bash
   ansible-playbook site.yml --ask-vault-pass --check --diff
   ```

6. **Despliega**:

   ```bash
   ansible-playbook site.yml --ask-vault-pass
   ```

   Despliegue gradual recomendado la primera vez:

   ```bash
   ansible-playbook site.yml --ask-vault-pass --limit mail1.cliente-a.pe
   ```

## Operación

- **Actualizar a una versión nueva**: `make package` en el repo y vuelve a
  ejecutar el playbook. Al cambiar el binario o la config, los handlers reinician
  `sendguard-agent` y `sendguard-policyd` automáticamente.
- **Cambiar un umbral o whitelist**: edita group_vars/host_vars y re-ejecuta; solo
  se reescribe `agent.yaml` (con backup) y se reinician los servicios.
- **Verificar un host**:

  ```bash
  ansible sendguard -a 'systemctl is-active sendguard-agent sendguard-policyd' --become
  ```

## Notas

- `agent.yaml` queda marcado como gestionado por Ansible; no lo edites a mano en
  el host (se sobrescribe en el próximo despliegue).
- La detección de país usa la DB local MaxMind. La lista `trusted_cidrs` de
  Microsoft Exchange Online viene en el rol (defaults) para evitar falsos
  positivos de viaje imposible con Outlook Mobile.
- `inventory.ini`, `group_vars/all.yml`, `host_vars/*.yml` (reales) y los
  binarios **no** se versionan (ver `.gitignore`).
