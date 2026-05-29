# Integración con Postfix — Policy Daemon y Rate-Limit

Esta guía cubre la configuración **única** que hay que aplicar en cada servidor
Zimbra para activar dos integraciones opcionales de SendGuard con Postfix:

1. **Policy Daemon** (`sendguard-policyd`) — rechazo en tiempo real de IPs bloqueadas,
   antes de que el cliente llegue a enviar `MAIL FROM`.
2. **Rate-limit por cuenta** — rechazo de envíos de cuentas marcadas por el agente
   mediante una tabla de acceso (`check_sender_access`).

> Todos los comandos `zmprov mcf` se ejecutan **una sola vez** como usuario `zimbra`
> y persisten en la configuración de Zimbra. Tras aplicarlos hay que recargar el MTA
> (`zmmtactl reload` o `postfix reload`).

---

## 1. Policy Daemon (rechazo en tiempo real)

### Cómo funciona

`sendguard-policyd` escucha en un socket TCP local (por defecto `127.0.0.1:9100`)
hablando el [protocolo de política de Postfix](https://www.postfix.org/SMTPD_POLICY_README.html).
Por cada conexión SMTP entrante, Postfix le envía los atributos de la sesión y el
daemon responde:

- `REJECT …` si la IP del cliente está bloqueada por el agente.
- `DUNNO` en cualquier otro caso (incluido cualquier error → **fail-open**: si el
  daemon o el agente no responden, el correo **no** se interrumpe).

El daemon consulta al agente vía `GET /blocked/{ip}` en su API HTTP y **cachea la
respuesta 10 s** para no saturar la API durante ataques de alta frecuencia.

```
Postfix smtpd ──(client_address)──▶ sendguard-policyd ──GET /blocked/{ip}──▶ sendguard-agent
                ◀──(REJECT|DUNNO)──                    ◀──(blocked: true|false)──
```

### Configuración en Postfix

```bash
# Como usuario zimbra:
zmprov mcf zimbraMtaSmtpdRecipientRestrictions \
  "check_policy_service inet:127.0.0.1:9100" \
  "permit_mynetworks" \
  "permit_sasl_authenticated" \
  "reject_unauth_destination"

# Recargar el MTA
zmmtactl reload
```

> **Orden importante**: `check_policy_service` debe ir **antes** de
> `permit_mynetworks`/`permit_sasl_authenticated` solo si quieres bloquear también
> a remitentes autenticados/locales. En la mayoría de despliegues interesa bloquear
> atacantes externos, así que el orden de arriba (policy primero) es el recomendado:
> una IP baneada se rechaza aunque intente autenticarse.

### Configuración del daemon (`agent.yaml`)

```yaml
policy_daemon:
  listen: "127.0.0.1:9100"   # vacío = daemon deshabilitado

api:
  listen: "127.0.0.1:9099"   # el daemon consulta GET /blocked/{ip} aquí
```

El daemon lee `agent.yaml` para descubrir la dirección de la API del agente
(`api.listen`). Si `api.listen` está vacío usa `http://127.0.0.1:9099` por defecto.
También se puede sobreescribir la escucha con `-listen`:

```bash
sendguard-policyd -config /etc/sendguard/agent.yaml -listen 127.0.0.1:9100
```

### Servicio systemd

El daemon corre como una unidad aparte del agente
(`deploy/sendguard-policyd.service`). Verifica que esté activo:

```bash
systemctl status sendguard-policyd
journalctl -u sendguard-policyd -f
```

### Verificación

```bash
# Con el agente y el daemon arriba, bloquea una IP de prueba (TEST-NET):
sendguard-ctl block 203.0.113.10

# Simula una solicitud de política (la conexión se cierra tras la línea en blanco):
printf 'request=smtpd_access_policy\nclient_address=203.0.113.10\n\n' | nc 127.0.0.1 9100
# Esperado: action=REJECT Blocked by SendGuard — contact your administrator

printf 'request=smtpd_access_policy\nclient_address=8.8.8.8\n\n' | nc 127.0.0.1 9100
# Esperado: action=DUNNO
```

---

## 2. Rate-limit por cuenta (`check_sender_access`)

### Cómo funciona

Cuando un módulo emite la acción `rate_limit`, el agente añade la cuenta a una tabla
de acceso de Postfix (`<postfix_conf>/sendguard_access`) y regenera el mapa con
`postmap`. Postfix entonces rechaza los envíos de esa cuenta hasta que el ban expira
(`firewall.ban_seconds`), momento en que el agente elimina la entrada automáticamente.

### Configuración en Postfix

```bash
# Como usuario zimbra:
zmprov mcf zimbraMtaSmtpdSenderRestrictions \
  "check_sender_access lmdb:/opt/zimbra/common/conf/sendguard_access" \
  "permit_sasl_authenticated" \
  "reject_unauthenticated_sender_login_mismatch"

zmmtactl reload
```

> La ruta del mapa debe coincidir con `zimbra.postfix_conf` de `agent.yaml`
> (por defecto `/opt/zimbra/common/conf`). El agente crea y mantiene el archivo
> `sendguard_access`; no hace falta crearlo a mano.

### Configuración relacionada (`agent.yaml`)

```yaml
zimbra:
  postfix_sbin: "/opt/zimbra/common/sbin"   # postmap, postqueue, postsuper
  postfix_conf: "/opt/zimbra/common/conf"   # aquí se crea sendguard_access

firewall:
  ban_seconds: 3600   # también define cuánto dura el rate-limit
```

### Notas

- El rate-limit y el `purge_queue` requieren que `postfix_sbin` y `postfix_conf`
  estén configurados; si faltan, esas acciones se omiten con un warning en el log.
- Ningún módulo de la Fase 2 emite `rate_limit` ni `purge_queue` automáticamente por
  defecto (son acciones de infraestructura disponibles para reglas futuras y para uso
  manual vía API). El bloqueo de IP y la suspensión de cuenta sí son automáticos.

---

## Resumen de puertos

| Componente | Puerto por defecto | Bind | Propósito |
|------------|--------------------|------|-----------|
| API del agente | `9099` | `127.0.0.1` | observabilidad + control + consulta del policyd |
| Policy daemon | `9100` | `127.0.0.1` | `check_policy_service` de Postfix |

Ambos escuchan solo en localhost. **Nunca** los expongas en una interfaz pública sin
autenticación (`api.api_key`) y un firewall delante.
