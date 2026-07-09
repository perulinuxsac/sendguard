# Changelog

Todas las versiones notables de SendGuard se documentan en este archivo.

El formato sigue [Keep a Changelog](https://keepachangelog.com/es/1.1.0/)
y el proyecto usa [Versionado Semántico](https://semver.org/lang/es/).

Las versiones v1.0.6 – v1.0.10 surgieron de la respuesta a un incidente de
compromiso masivo de cuentas en `webmail.perucloud.pe` (12 jun 2026), en el
que cuentas hackeadas enviaban spam falseando el `From` del sobre.

## [1.0.12] - 2026-07-09

Segunda tanda de correcciones de la auditoría de código interna (revisión
completa de los 15 paquetes, los 3 binarios y el deploy).

### Corregido
- **Timeout (60 s) y `WaitDelay` en los tres envíos por sendmail** (alerta al
  admin, aviso al usuario suspendido, reporte diario). La alerta al admin se
  envía desde el goroutine del enforcer: un sendmail colgado congelaba el
  pipeline de contención igual que los comandos ya corregidos en esta versión.
  `WaitDelay` cubre además un hueco de todos los comandos externos: matar el
  proceso por timeout no basta si un hijo huérfano (postdrop, el java de
  zmprov) hereda los pipes — `Wait()` seguía bloqueado esperándolos. Aplica a
  sendmail, zmprov, firewall-cmd/ufw y postqueue/postmap/postsuper.
- **`whitelist add` con una IP mal tipeada ("300.1.2.3", "10.0.0.0/33") ya no
  se guarda en silencio como CUENTA**: responde 400. El operador creía haber
  exonerado la IP y la entrada persistida no protegía nada. El remove sigue
  aceptando cualquier valor para poder limpiar entradas defectuosas antiguas.
- **ufw: los bloqueos ahora se insertan al INICIO de la lista de reglas**
  (`ufw insert 1`). `ufw deny` a secas añade la regla al final, detrás de los
  `allow` de los puertos de correo, y como ufw aplica la primera coincidencia
  la IP "bloqueada" seguía conectando a 25/465/587/993 — en hosts ufw la
  contención de firewall era inefectiva. Con cero reglas numeradas se cae al
  append simple (único caso equivalente).
- **Los rate-limits sobreviven reinicios del agente.** La expiración vivía
  solo en un `time.AfterFunc` en memoria mientras la entrada REJECT de
  `sendguard_access` persiste en disco: tras un restart (p. ej. cada redeploy
  de Ansible) la cuenta quedaba sin poder enviar indefinidamente. Ahora la
  expiración se persiste en SQLite (tabla `rate_limits`); al arrancar se
  limpian las vencidas y se reprograman las vigentes.
- **Timeout (2 min) en todos los comandos del path automático de alertas**
  (zmprov, firewall-cmd, ufw, postmap, postqueue/postsuper). `handle()` corre
  en un único goroutine: sin límite, un comando colgado congelaba toda la
  contención para siempre y las alertas siguientes se descartaban en silencio.
  Los paths manuales ya lo tenían; `Unsuspend` ahora también se desacopla del
  request HTTP como Block/Unblock.
- **`Block()` manual propaga el fallo del firewall**: la API y el ctl ya no
  reportan "bloqueada" cuando `firewall-cmd`/`ufw` fallaron (el estado interno
  se revierte, como antes).
- **El throttle de notificaciones consume el cooldown solo tras un envío
  exitoso** — un fallo transitorio de sendmail/Telegram ya no suprime la
  alerta durante 5 minutos — **y la clave de cooldown ahora es
  acción+IP+cuenta**: antes era IP-primero y en un incidente con varias
  cuentas comprometidas desde la misma IP solo se notificaba la primera.
- **`suspendAccount` depura repeticiones**: alertas repetidas sobre una cuenta
  ya suspendida no re-ejecutan zmprov ni reenvían el aviso al usuario
  (correos duplicados); la IP de la alerta sí se sigue bloqueando.
- La purga de cola por dominio matchea el dominio del destinatario por
  sufijo exacto (`@dominio`), no por subcadena: `user@cliente.pe.evil.net`
  ya no cuenta como `cliente.pe`.
- `GET /whitelist` excluye las IPs actualmente bloqueadas (el enforcer las
  añade a la whitelist del engine solo para silenciar sus eventos durante el
  ban; no son whitelist del operador y verlas ahí confundía).

### Seguridad
- El aviso al usuario suspendido pasa el destinatario a sendmail tras `--`,
  de modo que una cuenta que empiece con `-` no se interprete como opción.

### Eliminado
- `zimbra.workers` (config y variable de Ansible `sendguard_zimbra_workers`):
  configuración muerta, no se usaba en ningún sitio.

## [1.0.11] - 2026-07-09

Correcciones surgidas de una auditoría de código interna.

### Corregido
- **Las alertas con IP de país permitido ahora SÍ se notifican.** Antes,
  además de omitirse la contención (bloqueo/suspensión/rate-limit), se
  suprimía también la notificación push: un atacante operando desde una IP
  nacional (o un VPS/VPN local) pasaba completamente desapercibido — solo
  quedaba rastro en el audit log. Ahora la notificación se envía siempre,
  con la marca «⚠ contención omitida: IP de país permitido (XX) — revisar
  manualmente» en las razones (registrada también en el audit log y el
  forwarder). La contención sigue omitiéndose igual que antes.

### Seguridad
- **API key autogenerada para los endpoints de escritura de la API local.**
  Con `api.api_key` vacío, cualquier proceso local del servidor podía
  desbloquear IPs, rehabilitar cuentas o whitelistar al atacante
  (`DELETE /blocked/{ip}`, `DELETE /suspended/{account}`,
  `POST /whitelist/{v}`) y desactivar SendGuard tras un compromiso parcial
  del host. Ahora `install.sh` y el rol de Ansible generan una clave
  aleatoria por host (persistida en `/etc/sendguard/api.key`, modo 0600,
  reutilizada en upgrades y redeploys) y la escriben en `api.api_key`. El
  agente advierte al arrancar si la API corre sin clave.
- `sendguard-ctl` resuelve la API key automáticamente: `-key` >
  `$SENDGUARD_API_KEY` > `/etc/sendguard/api.key`. Como root los comandos de
  escritura funcionan sin flags (`sendguard-ctl block <ip>`); el archivo es
  0600 root, así que ningún otro usuario local hereda ese acceso.
- El rol de Ansible escribe siempre la clave efectiva en
  `/etc/sendguard/api.key`, también cuando se fija una clave de flota con
  `sendguard_api_key` (antes en ese caso el archivo no se creaba o quedaba
  con una clave autogenerada vieja, rompiendo el flujo del ctl).
- La comparación de la API key usa `crypto/subtle.ConstantTimeCompare`
  (antes `!=`, susceptible de timing attack si la API se expone fuera de
  loopback).

## [1.0.10] - 2026-06-12

### Añadido
- Backend de firewall **`firewalld-ipset`**: un único set `hash:net` (acepta
  IPs y CIDRs) enlazado a la zona `drop`, en lugar de una rich rule por IP.
  Altas y bajas son O(1) sin importar cuántas IPs haya bloqueadas. En
  `webmail.perucloud.pe` firewalld había acumulado 16,267 rich rules y cada
  `firewall-cmd` tardaba ~7 s; tras la migración bajó a ~0,2 s. Es el backend
  por defecto en RHEL/Rocky/CentOS (sobreescribible con
  `sendguard_firewall_backend: firewalld` para volver a rich rules).
- `Setup` idempotente del ipset al arrancar y `resyncFirewall`, que repuebla
  el set desde SQLite tras un reload o reboot.
- Script `deploy/purge_richrules.sh` para eliminar las rich rules de bloqueo
  acumuladas (con backup del XML, solo reglas `source` + `reject`/`drop`).

### Corregido
- El script de purga ya no toca firewalld en hosts donde `ufw` es el firewall
  activo (Ubuntu/Debian). En un host con firewalld y ufw coexistiendo, el
  `firewall-cmd --reload` recargaba las cadenas de iptables que gestiona ufw y
  cortaba la comunicación. Ahora aborta si ufw está activo.

## [1.0.9] - 2026-06-12

### Añadido
- Aviso por correo **al propio usuario** cuando su cuenta es suspendida por
  compromiso (`notification.email.notify_suspended_user`), solo en la acción
  `suspend_account` y solo si la suspensión tuvo éxito. La cuenta `locked`
  sigue recibiendo correo, así que el usuario lo verá tras el reseteo de
  contraseña y el atacante no puede leerlo. Diseño HTML estilo alerta de
  seguridad de Google (tarjeta centrada, botón de contacto, CSS inline sin
  imágenes externas) más versión en texto plano.
- Remitente y contacto de soporte propios para ese aviso
  (`user_notice_from`), independientes del `from` de las alertas a
  administradores.

### Corregido
- Los bloqueos manuales (`Block`/`Unblock`) se desacoplan del contexto del
  request HTTP: en hosts con firewalld lento, el timeout del cliente mataba el
  segundo `firewall-cmd` de un bloqueo permanente a mitad de camino. Los
  timeouts de la API y de `sendguard-ctl` se ampliaron a 150 s.

## [1.0.8] - 2026-06-12

### Corregido
- Los bloqueos manuales vía `sendguard-ctl`/API ya no se vetan por
  `allowed_countries`. En hosts con `allowed_countries: [PE]`, bloquear una IP
  o rango peruano se omitía en silencio y el `ctl` reportaba éxito sin haber
  bloqueado nada. El veto por país aplica solo a las alertas automáticas; un
  bloqueo manual es una decisión explícita del administrador.

## [1.0.7] - 2026-06-12

### Añadido
- `sendguard-ctl block` y `unblock` aceptan **rangos CIDR** además de IPs
  individuales (ej: `200.25.47.0/24`), necesario porque el atacante rotaba
  entre varias IPs del mismo `/24`. Una IP individual consultada por el policy
  daemon hace match contra los rangos bloqueados; los CIDRs se normalizan,
  persisten en SQLite y se restauran tras reinicio.

## [1.0.6] - 2026-06-12

### Corregido
- El correo saliente autenticado se atribuye a la **cuenta SASL** que
  autenticó la sesión, no al `From` del sobre (falseable). En el incidente, una
  cuenta comprometida enviaba spam con `from=<leslie@usanpedro.edu.pe>` (cuenta
  inexistente en el servidor) mientras autenticaba como
  `jalegre@sedachimbote.com.pe`; al atribuir los envíos al `From` falseado,
  `number_messages` alertaba sobre una cuenta fantasma y la cuenta real seguía
  enviando sin ser detectada. El remitente del sobre se conserva en
  `Extra["from"]`.

[1.0.10]: https://github.com/perulinuxsac/sendguard/compare/v1.0.9...v1.0.10
[1.0.9]: https://github.com/perulinuxsac/sendguard/compare/v1.0.8...v1.0.9
[1.0.8]: https://github.com/perulinuxsac/sendguard/compare/v1.0.7...v1.0.8
[1.0.7]: https://github.com/perulinuxsac/sendguard/compare/v1.0.6...v1.0.7
[1.0.6]: https://github.com/perulinuxsac/sendguard/compare/v1.0.5...v1.0.6
