# Despliegue de SendGuard con Ansible

Rol idempotente para instalar/actualizar el agente SendGuard en una flota de
servidores **Zimbra** (Rocky/RHEL con firewalld o Ubuntu/Debian con ufw).

Hace lo mismo que `deploy/install.sh` pero desatendido y repetible: copia los
binarios, descarga la DB GeoIP MaxMind (+ cron de actualización), genera
`/etc/sendguard/agent.yaml` y la API key local (`/etc/sendguard/api.key`),
instala el servicio systemd `sendguard-agent` y lo habilita y arranca.

Backend de firewall por defecto: `firewalld-ipset` en Rocky/RHEL y `ufw` en
Ubuntu/Debian (se puede forzar con `sendguard_firewall_backend` en host_vars).

SendGuard **no interviene el SMTP**: no toca la configuración de Postfix, la cola
ni el antispam. La contención es solo firewall (ipset/ufw) y suspensión de
cuenta (zmprov). En hosts con versiones < 1.1.0 el rol ejecuta
`deploy/remove_smtp_hooks.sh`, que quita de Postfix el
`check_policy_service inet:…:9100` y el `sendguard_access` (plantillas de
zmconfigd, LDAP y `main.cf`), recarga Postfix, verifica y **recién entonces**
detiene y elimina `sendguard-policyd`. Todo eso ocurre antes de copiar los
binarios nuevos. Si no puede quitar el hook (sin `postconf`, hook en un override
de `master.cf`…), el play falla sin detener policyd, para no cortar el correo.

## Requisitos

- Ansible 2.12+ en el control node.
- Acceso SSH (root o usuario con sudo) a cada host.
- Cada host es un servidor Zimbra con firewall activo (firewalld o ufw).
- Binarios compilados en `dist/` del repo: ejecuta en la raíz del repo

  ```bash
  make package      # compila agent y ctl → dist/
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

## Verificación post-deploy

El rol incluye **dos niveles**:

- **Smoke-check (automático, seguro)** — corre al final de cada despliegue. No
  modifica nada: confirma que `sendguard-agent` está activo, que Postfix no
  referencia a SendGuard ni queda `sendguard-policyd`
  (`remove_smtp_hooks.sh --check`), reporta la versión instalada y sondea el
  endpoint `GET /health` de la API. Si algo falla, el playbook falla.

- **Self-test integral (opt-in, intrusivo)** — ejecuta `deploy/test_sendguard.sh`
  en el host: baja umbrales, reinicia el agente, inyecta ataques sintéticos para
  validar 9 de los 11 módulos de detección y restaura los umbrales al terminar.

  ```bash
  ansible-playbook site.yml --ask-vault-pass --tags selftest --limit staging-mail1
  ```

  > ⚠ **No lo corras en producción con cuentas reales.** El script inyecta
  > ataques que provocan bloqueos de IPs de prueba y **suspensión de cuentas de
  > prueba** (`admin@`, `bulk@`, `ceo@`, `flood@`, `spammer@`…). Si alguna existe
  > de verdad en ese servidor, quedará bloqueada. Úsalo en un host de staging o
  > recién instalado. Por eso está excluido de los deploys normales (tag `never`)
  > y solo se ejecuta con `--tags selftest`.

## Operación

- **Actualizar a una versión nueva**: `make package` en el repo y vuelve a
  ejecutar el playbook. Al cambiar el binario o la config, los handlers reinician
  `sendguard-agent` automáticamente.
- **Cambiar un umbral o whitelist**: edita group_vars/host_vars y re-ejecuta; solo
  se reescribe `agent.yaml` (con backup) y se reinicia el agente.
- **Verificar un host**:

  ```bash
  ansible sendguard -a 'systemctl is-active sendguard-agent' --become
  ```

## Notas

- `agent.yaml` queda marcado como gestionado por Ansible; no lo edites a mano en
  el host (se sobrescribe en el próximo despliegue).
- La detección de país usa la DB local MaxMind. La lista `trusted_cidrs` de
  Microsoft Exchange Online viene en el rol (defaults) para evitar falsos
  positivos de viaje imposible con Outlook Mobile.
- `inventory.ini`, `group_vars/all.yml`, `host_vars/*.yml` (reales) y los
  binarios **no** se versionan (ver `.gitignore`).
