# Guía de enrolamiento — Cliente nuevo con Ansible

Guía completa y copiable para desplegar SendGuard en el servidor Zimbra de un
**cliente nuevo** (host que nunca tuvo SendGuard, aún sin enrolar al Controller).

El rol es **idempotente** y **autodetecta** el OS, el firewall y las rutas de
Zimbra. Re-ejecutarlo es seguro: solo aplica lo que cambió.

---

## 0. Requisitos

**En el control node** (la máquina desde donde lanzas Ansible — puede ser tu
laptop o el propio repo en `/root/sendguard`):

- Ansible 2.12+ (`ansible-playbook --version`).
- Acceso SSH al servidor del cliente como `root` o usuario con `sudo`.
- Binarios compilados en `dist/` (paso 1).

**En el servidor del cliente** (lo verifica el preflight; si falta algo, aborta):

- Zimbra instalado en `/opt/zimbra`.
- Firewall activo: `firewalld` (Rocky/RHEL/Alma) o `ufw` (Ubuntu/Debian).
- Log de correo en `/var/log/maillog` o `/var/log/mail.log`.

> Todo lo demás (rutas de Postfix, backend de firewall, `mailbox.log`, `zmprov`)
> lo autodetecta el rol.

---

## 1. Compilar los binarios (una vez por release)

En la raíz del repo:

```bash
cd /root/sendguard
make package        # → dist/sendguard-agent, sendguard-ctl, sendguard-policyd
```

El rol aborta el despliegue si falta cualquiera de los tres en `dist/`.

---

## 2. Inventario — añadir el host del cliente

```bash
cd /root/sendguard/deploy/ansible
cp inventory.example.ini inventory.ini   # solo la primera vez
$EDITOR inventory.ini
```

Añade el servidor del cliente bajo `[sendguard]`:

```ini
[sendguard]
mail1.cliente-nuevo.pe   ansible_host=200.123.45.67

[sendguard:vars]
ansible_user=root
# Si entras con un usuario sudo en vez de root:
# ansible_user=deploy
# ansible_become=true
```

> El **nombre de inventario** (`mail1.cliente-nuevo.pe`) se convierte en el
> `server_id` por defecto y aparece en reportes/alertas. Usa una convención
> tipo `mailN.<cliente>.<tld>`.

---

## 3. Aceptar la host key SSH del servidor nuevo

`host_key_checking` está activado, así que la primera conexión a un host nuevo
fallará si su clave no está en `known_hosts`. Pre-cárgala:

```bash
ssh-keyscan -H 200.123.45.67 >> ~/.ssh/known_hosts
```

(O conéctate una vez a mano con `ssh root@200.123.45.67` y acepta el fingerprint.)

---

## 4. Variables compartidas de la flota (`group_vars/all.yml`)

Si es el **primer** cliente que despliegas, crea y cifra el archivo de secretos
compartidos (Telegram, MaxMind, AbuseIPDB, email). Si ya existe de otros
clientes, **sáltate este paso**.

```bash
cp group_vars/all.example.yml group_vars/all.yml
$EDITOR group_vars/all.yml          # rellena tokens y credenciales reales
ansible-vault encrypt group_vars/all.yml
```

Contenido típico (los secretos van aquí, cifrados):

```yaml
sendguard_client_name: "PERULINUX"          # default; se sobreescribe por host
sendguard_allowed_countries: ["PE", "US"]

sendguard_telegram_token: "123456:ABC..."
sendguard_telegram_chat_id: "8480654669"
sendguard_maxmind_account_id: "1234567"
sendguard_maxmind_license_key: "..."
sendguard_abuseipdb_key: "..."
sendguard_email_from: "ti@perucloud.pe"
sendguard_email_to: ["soc@perulinux.pe"]
```

---

## 5. Variables específicas del cliente (`host_vars/<host>.yml`)

Crea `host_vars/mail1.cliente-nuevo.pe.yml` (mismo nombre que en el inventario).
Solo lo que **difiera** del `all.yml` compartido:

```yaml
# Obligatorio: el preflight falla si client_name queda vacío.
sendguard_client_name: "Cliente Nuevo SAC"

# server_id por defecto = nombre de inventario; descomenta para forzar otro:
# sendguard_server_id: "cliente-nuevo-mail1"

# Redes de oficina y cuentas exentas de detección (propias del cliente):
sendguard_whitelist_ips:
  - "200.123.45.0/24"
sendguard_whitelist_accounts:
  - "backup@cliente-nuevo.pe"
  - "newsletter@cliente-nuevo.pe"

# Si el cliente notifica a su propio SOC en vez del global:
# sendguard_email_to: ["soc@cliente-nuevo.pe"]

# Si su política de países difiere de la global:
# sendguard_allowed_countries: ["PE", "US", "ES"]
```

> Es opcional salvo `sendguard_client_name`. Sin host_vars, el host hereda todo
> lo de `all.yml` y `server_id` = nombre de inventario.

---

## 6. Modo standalone vs. enrolado al Controller

Un cliente **recién instalado arranca en modo standalone** — es el valor por
defecto, no toques nada. El agente detecta y contiene amenazas localmente y
persiste las alertas en SQLite (`/var/lib/sendguard/sendguard.db`).

**Enrolarlo al Controller central se hace después y sin reinstalar.** Cuando esté
listo, añade en `host_vars` (o `all.yml` si es para toda la flota):

```yaml
sendguard_controller_url: "https://controller.perulinux.pe"
sendguard_controller_api_key: "<token-del-cliente>"
```

y re-ejecuta el playbook (paso 8): solo reescribe `agent.yaml` y reinicia los
servicios. El agente sincroniza automáticamente las alertas acumuladas.

---

## 7. Prueba en seco (no cambia nada)

```bash
ansible-playbook site.yml --ask-vault-pass --check --diff \
  --limit mail1.cliente-nuevo.pe
```

Revisa el `--diff`: deberías ver la creación de directorios, copia de binarios,
generación de `agent.yaml` y las units de systemd. Si el preflight detecta que
falta Zimbra / firewall / maillog, falla aquí sin tocar el host.

---

## 8. Desplegar

```bash
ansible-playbook site.yml --ask-vault-pass --limit mail1.cliente-nuevo.pe
```

> **`--limit` es esencial**: despliega **solo** al cliente nuevo y no toca el
> resto de la flota. Sin él, el playbook corre sobre todos los hosts del grupo.

Lo que hace el rol, en orden:

1. Preflight + autodetección (OS, firewall, rutas Zimbra, mail log).
2. Verifica que los binarios existen en `dist/`.
3. Crea `/etc/sendguard` y `/var/lib/sendguard`.
4. Copia los binarios a `/usr/local/bin`.
5. Descarga la DB GeoIP MaxMind (si hay credenciales) + cron de actualización
   semanal.
6. Genera `/etc/sendguard/agent.yaml` desde el template.
7. Instala y habilita las units `sendguard-agent` y `sendguard-policyd`.
8. Smoke-check final (ver paso 9).

---

## 9. Verificación

### Automática (corre al final del deploy, no intrusiva)

El rol confirma que `sendguard-agent` y `sendguard-policyd` están `active`,
reporta la versión instalada y sondea `GET /health` de la API. Si algo falla, el
playbook falla.

Comprobación manual rápida en cualquier momento:

```bash
ansible mail1.cliente-nuevo.pe -a \
  'systemctl is-active sendguard-agent sendguard-policyd' --become
```

O ya dentro del servidor por SSH:

```bash
ssh root@200.123.45.67
systemctl status sendguard-agent sendguard-policyd
journalctl -u sendguard-agent -f
curl -s http://127.0.0.1:9099/health
/usr/local/bin/sendguard-ctl status
```

### Self-test integral (opt-in, INTRUSIVO)

Valida los módulos de detección inyectando ataques sintéticos. **Solo en un host
de staging o recién instalado SIN cuentas reales** — suspende cuentas de prueba
(`admin@`, `ceo@`, `bulk@`, `flood@`, `spammer@`…) si existen de verdad.

```bash
ansible-playbook site.yml --ask-vault-pass --tags selftest \
  --limit staging-cliente-nuevo
```

Está excluido de los deploys normales (tag `never`); solo corre con `--tags selftest`.

---

## 10. Operación posterior

- **Actualizar a una versión nueva**: `make package` en el repo y re-ejecuta el
  playbook. Al cambiar el binario o la config, los handlers reinician los
  servicios automáticamente.
- **Cambiar un umbral / whitelist / enrolar al Controller**: edita
  `group_vars` o `host_vars` y re-ejecuta. Solo se reescribe `agent.yaml` (con
  backup) y se reinician los servicios.
- **No edites `/etc/sendguard/agent.yaml` a mano en el host**: está gestionado
  por Ansible y se sobrescribe en el próximo despliegue. Cambia las variables.

---

## 11. Troubleshooting

| Síntoma | Causa probable / arreglo |
|---|---|
| `No se encontró Zimbra en /opt/zimbra` | El host no es un Zimbra o está en otra ruta. El rol requiere Zimbra. |
| `ufw status` / `firewalld` falla en preflight | El firewall no está activo. Actívalo: `ufw enable` o `systemctl enable --now firewalld`. |
| `Falta sendguard-agent en .../dist` | No corriste `make package` (paso 1). |
| `sendguard_client_name es obligatorio` | Falta definirlo en `host_vars` (paso 5). |
| `could not read Username for https://github.com` | Es un push del repo, no del deploy. No afecta al despliegue desde este control node. |
| Host key prompt / timeout SSH | Falta aceptar la host key (paso 3). |
| Viaje imposible con Outlook Mobile | Cubierto: la lista `trusted_cidrs` de Exchange Online viene en los defaults del rol. |

---

## Resumen TL;DR

```bash
# 1. Compilar (una vez por release)
cd /root/sendguard && make package

# 2-5. Inventario + vars del cliente
cd deploy/ansible
$EDITOR inventory.ini                              # añadir el host
ssh-keyscan -H <IP> >> ~/.ssh/known_hosts          # aceptar host key
$EDITOR host_vars/mail1.cliente-nuevo.pe.yml       # client_name + whitelist

# 6. Prueba en seco
ansible-playbook site.yml --ask-vault-pass --check --diff --limit mail1.cliente-nuevo.pe

# 7. Desplegar
ansible-playbook site.yml --ask-vault-pass --limit mail1.cliente-nuevo.pe

# 8. Verificar
ansible mail1.cliente-nuevo.pe -a 'systemctl is-active sendguard-agent sendguard-policyd' --become
```
