# Changelog

Todas las versiones notables de SendGuard se documentan en este archivo.

El formato sigue [Keep a Changelog](https://keepachangelog.com/es/1.1.0/)
y el proyecto usa [Versionado Semántico](https://semver.org/lang/es/).

Las versiones v1.0.6 – v1.0.10 surgieron de la respuesta a un incidente de
compromiso masivo de cuentas en `webmail.perucloud.pe` (12 jun 2026), en el
que cuentas hackeadas enviaban spam falseando el `From` del sobre.

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
