// Package enforcement ejecuta las acciones de contención sobre el servidor Zimbra.
// Soporta bloqueo de IPs vía firewalld (RHEL) o ufw (Ubuntu/Debian) y suspensión
// de cuentas vía zmprov. El Enforcer es la única pieza del sistema que ejecuta
// comandos del SO.
package enforcement

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/perulinux/sendguard/internal/abuseipdb"
	"github.com/perulinux/sendguard/internal/audit"
	"github.com/perulinux/sendguard/internal/detection"
	"github.com/perulinux/sendguard/internal/geoip"
	"github.com/perulinux/sendguard/internal/notify"
	"github.com/perulinux/sendguard/internal/store"
)

// AlertForwarder persiste alertas para el StoreAndForward hacia el Controller.
type AlertForwarder interface {
	SaveAlert(a detection.Alert)
}

// IPWhitelist es el subconjunto de detection.Whitelist que necesita el Enforcer.
// Permite añadir y quitar IPs en caliente sin importar el paquete detection completo
// (aunque en la práctica siempre se pasa un *detection.Whitelist).
type IPWhitelist interface {
	AddIP(ip string) error
	RemoveIP(ip string)
}

// UserNotifier envía avisos dirigidos al usuario final afectado (no al admin).
// Lo implementa email.Notifier; nil deshabilita los avisos.
type UserNotifier interface {
	NotifySuspendedUser(ctx context.Context, account string, alert detection.Alert) error
}

// Config agrupa los parámetros del Enforcer.
type Config struct {
	FirewallBackend  string            // "firewalld" (RHEL) o "ufw" (Ubuntu); default: firewalld
	BanSeconds       int               // duración del bloqueo de IP (0 = permanente)
	ZmprovBin        string            // ruta completa a zmprov (default: /opt/zimbra/bin/zmprov)
	PostfixSbin      string            // /opt/zimbra/common/sbin — binarios de Postfix de Zimbra
	PostfixConf      string            // /opt/zimbra/common/conf — config de Postfix de Zimbra
	Notifier         notify.Notifier   // nil usa Noop (sin notificaciones)
	AbuseIPDB        *abuseipdb.Client // nil deshabilita la consulta de reputación
	AuditLog         *audit.Logger     // nil deshabilita el audit log
	Store            *store.Store      // nil deshabilita la persistencia local SQLite
	Forwarder        AlertForwarder    // nil deshabilita el StoreAndForward
	Whitelist        IPWhitelist       // nil deshabilita la sincronización con el engine
	GeoResolver      *geoip.Resolver   // nil deshabilita la verificación de país en bloqueos
	AllowedCountries []string          // IPs de estos países no se bloquean en firewall (solo notificación)
	UserNotifier     UserNotifier      // nil deshabilita el aviso al usuario suspendido
	// NotifyOnActions filtra las notificaciones push (Telegram/email/webhook) por acción.
	// Si está vacío se notifica todo. Valores activos: block_ip | suspend_account | rate_limit | notify_only
	NotifyOnActions []string // vacío = notificar todo
}

// blockedIP registra cuándo expira el baneo de una IP para evitar
// llamadas duplicadas al firewall.
type blockedIP struct {
	expiry time.Time
	module string
}

// suspendedAcct registra una cuenta suspendida por el agente.
type suspendedAcct struct {
	module    string
	timestamp time.Time
}

// SuspendedAcctInfo describe una cuenta suspendida actualmente.
type SuspendedAcctInfo struct {
	Account   string
	Module    string
	Timestamp time.Time
}

// EnforcerStats agrupa los contadores de acciones ejecutadas.
type EnforcerStats struct {
	BlocksTotal      int64
	SuspensionsTotal int64
	RateLimitsTotal  int64
}

// Enforcer recibe alertas del Engine y ejecuta acciones de contención.
// Es thread-safe.
type Enforcer struct {
	cfg            Config
	fw             fw
	mu             sync.Mutex
	blockedIPs     map[string]blockedIP  // clave: IP o CIDR bloqueado
	blockedNets    map[string]*net.IPNet // solo entradas CIDR de blockedIPs, parseadas para Contains()
	suspendedAccts map[string]suspendedAcct
	blocksTotal    atomic.Int64
	suspsTotal     atomic.Int64
	ratesTotal     atomic.Int64
}

// New crea un Enforcer con la configuración dada.
func New(cfg Config) *Enforcer {
	if cfg.Notifier == nil {
		cfg.Notifier = notify.Noop{}
	}
	return &Enforcer{
		cfg:            cfg,
		fw:             newFW(cfg.FirewallBackend),
		blockedIPs:     make(map[string]blockedIP),
		blockedNets:    make(map[string]*net.IPNet),
		suspendedAccts: make(map[string]suspendedAcct),
	}
}

// Run procesa alertas hasta que ctx sea cancelado.
// Lanza también un goroutine de mantenimiento que limpia los bans expirados.
// Con ufw esto incluye eliminar la regla del firewall (ufw no tiene --timeout
// nativo); con firewalld la regla expira sola y solo se limpia el estado interno
// (mapa en memoria + whitelist del engine + SQLite).
func (e *Enforcer) Run(ctx context.Context, alertCh <-chan detection.Alert) {
	go e.runUnbanLoop(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case alert, ok := <-alertCh:
			if !ok {
				return
			}
			e.handle(ctx, alert)
		}
	}
}

// runUnbanLoop comprueba cada 30 s si hay bans expirados y limpia su estado.
// Para ufw elimina además la regla del firewall; para firewalld la regla ya
// expiró por --timeout y solo se purga el estado interno del agente.
func (e *Enforcer) runUnbanLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.unbanExpired(ctx)
		}
	}
}

// unbanExpired desbloquea en el firewall las IPs cuyo tiempo de ban ha expirado.
func (e *Enforcer) unbanExpired(ctx context.Context) {
	now := time.Now()
	e.mu.Lock()
	var expired []string
	for ip, entry := range e.blockedIPs {
		if now.After(entry.expiry) {
			expired = append(expired, ip)
			delete(e.blockedIPs, ip)
			delete(e.blockedNets, ip)
		}
	}
	e.mu.Unlock()

	for _, ip := range expired {
		// firewalld expira la regla con --timeout; solo ufw requiere eliminarla
		// explícitamente. Para firewalld nos limitamos a purgar el estado interno.
		if e.cfg.FirewallBackend == "ufw" {
			if err := e.fw.Unblock(ctx, ip); err != nil {
				slog.Warn("enforcement: fallo al desbloquear IP expirada", "ip", ip, "error", err)
			} else {
				slog.Info("enforcement: ban expirado, IP desbloqueada", "ip", ip)
			}
		} else {
			slog.Info("enforcement: ban expirado, estado interno purgado", "ip", ip)
		}
		if e.cfg.Store != nil {
			e.cfg.Store.DeleteBan(ip)
		}
		if e.cfg.Whitelist != nil {
			e.cfg.Whitelist.RemoveIP(ip)
		}
	}
}

// handle despacha la alerta al método correspondiente según la acción.
func (e *Enforcer) handle(ctx context.Context, alert detection.Alert) {
	slog.Info("enforcement: alerta recibida",
		"module", alert.Module,
		"action", alert.Action,
		"score", alert.Score,
		"ip", alert.IP,
		"account", alert.Account,
		"reasons", alert.Reasons,
	)

	switch alert.Action {
	case detection.ActionBlockIP:
		if alert.IP == "" {
			slog.Warn("enforcement: alerta block_ip sin IP, ignorando")
			return
		}
		e.blockIP(ctx, alert)

	case detection.ActionSuspendAcct:
		if alert.Account == "" {
			slog.Warn("enforcement: alerta suspend_account sin cuenta, ignorando")
			return
		}
		e.suspendAccount(ctx, alert)

	case detection.ActionRateLimit:
		if alert.Account == "" {
			slog.Warn("enforcement: rate_limit sin cuenta, ignorando")
			return
		}
		if e.isIPFromAllowedCountry(alert.IP) {
			country := e.cfg.GeoResolver.Country(alert.IP)
			slog.Info("enforcement: IP de país permitido, rate-limit omitido",
				"ip", alert.IP, "country", country, "account", alert.Account, "module", alert.Module)
			break
		}
		if e.cfg.PostfixSbin == "" || e.cfg.PostfixConf == "" {
			// break (no return): la alerta sigue registrándose en Forwarder/AuditLog,
			// igual que los fallos de block/suspend.
			slog.Warn("enforcement: rate_limit sin postfix_sbin/postfix_conf configurados, omitiendo")
			alert.Reasons = append(alert.Reasons, "⚠ rate-limit omitido: postfix_sbin/postfix_conf sin configurar")
			break
		}
		if err := rateLimit(ctx, alert.Account, e.cfg.BanSeconds, e.cfg.PostfixSbin, e.cfg.PostfixConf); err != nil {
			slog.Error("enforcement: fallo al aplicar rate-limit",
				"account", alert.Account, "error", err)
			alert.Reasons = append(alert.Reasons, fmt.Sprintf("⚠ fallo rate-limit: %v", err))
		} else {
			e.ratesTotal.Add(1)
			slog.Info("enforcement: rate-limit aplicado",
				"account", alert.Account, "ban_seconds", e.cfg.BanSeconds, "module", alert.Module)
		}

	case detection.ActionPurgeQueue:
		domain := alert.Domain
		if domain == "" {
			slog.Warn("enforcement: purge_queue sin dominio, ignorando")
			return
		}
		if e.cfg.PostfixSbin == "" || e.cfg.PostfixConf == "" {
			slog.Warn("enforcement: purge_queue sin postfix_sbin/postfix_conf configurados, omitiendo")
			alert.Reasons = append(alert.Reasons, "⚠ purga de cola omitida: postfix_sbin/postfix_conf sin configurar")
			break
		}
		n, err := purgeQueueDomain(ctx, domain, e.cfg.PostfixSbin, e.cfg.PostfixConf)
		if err != nil {
			slog.Error("enforcement: fallo al purgar cola", "domain", domain, "error", err)
			alert.Reasons = append(alert.Reasons, fmt.Sprintf("⚠ fallo al purgar cola: %v", err))
		} else {
			slog.Info("enforcement: cola purgada", "domain", domain, "deleted", n, "module", alert.Module)
		}

	case detection.ActionNotifyOnly:
		slog.Info("enforcement: notify_only — sin acción de contención")
	}

	if e.cfg.Forwarder != nil {
		e.cfg.Forwarder.SaveAlert(alert)
	}

	if e.cfg.AuditLog != nil {
		e.cfg.AuditLog.Log(ctx, alert)
	}

	// IPs de países permitidos: la contención ya fue omitida en blockIP/suspendAccount.
	// Omitir también la notificación push para no generar ruido por IPs legítimas.
	if e.isIPFromAllowedCountry(alert.IP) {
		return
	}

	// Filtro de notificaciones push: si NotifyOnActions está configurado, solo
	// se envían notificaciones para las acciones incluidas en la lista.
	// Forwarder y AuditLog siempre registran todo (sin filtro).
	if len(e.cfg.NotifyOnActions) > 0 {
		allowed := false
		for _, a := range e.cfg.NotifyOnActions {
			if string(alert.Action) == a {
				allowed = true
				break
			}
		}
		if !allowed {
			return
		}
	}

	// Enriquecer la notificación con el país de origen de la IP para dejar
	// constancia completa. El path de bloqueo lo resuelve vía AbuseIPDB sobre una
	// copia local, pero las suspensiones de cuenta no pasan por ahí; garantizamos
	// el dato aquí para cualquier alerta que efectivamente se notifique.
	if alert.IP != "" && alert.Country == "" && e.cfg.GeoResolver != nil {
		alert.Country = e.cfg.GeoResolver.Country(alert.IP)
	}

	if err := e.cfg.Notifier.Notify(ctx, alert); err != nil {
		slog.Warn("enforcement: error al notificar", "error", err, "module", alert.Module)
	}
}

// blockIP bloquea una IP usando el BanSeconds configurado globalmente.
func (e *Enforcer) blockIP(ctx context.Context, alert detection.Alert) {
	e.blockIPWithTTL(ctx, alert, e.cfg.BanSeconds)
}

// blockIPWithTTL bloquea una IP o un CIDR con un TTL explícito (0 = permanente).
func (e *Enforcer) blockIPWithTTL(ctx context.Context, alert detection.Alert, banSecs int) {
	if !ValidBlockTarget(alert.IP) {
		slog.Error("enforcement: IP/CIDR inválido, no se bloqueará", "ip", alert.IP)
		return
	}
	// Canonicalizar CIDRs ("200.25.47.5/24" → "200.25.47.0/24") para que la
	// deduplicación, el firewall y el unblock posterior usen la misma clave.
	alert.IP = normalizeTarget(alert.IP)

	// Las redes privadas (RFC 1918), loopback y link-local nunca se bloquean:
	// son tráfico interno (proxy Zimbra, webmail, oficina) y un ban aquí puede
	// dejar fuera de servicio el propio mail server. Aplica también a los
	// bloqueos manuales vía API y al ban de IP que acompaña a suspend_account.
	if isPrivateIP(baseIP(alert.IP)) {
		slog.Warn("enforcement: IP privada/local, bloqueo de firewall omitido",
			"ip", alert.IP, "module", alert.Module)
		return
	}

	// País permitido: no se bloquea en el firewall, no se persiste en SQLite y NO
	// se registra en el mapa de bloqueados — de lo contrario IsBlocked() devolvería
	// true y el policy daemon rechazaría las conexiones SMTP de esta IP pese a que
	// el bloqueo se omitió deliberadamente. La notificación sigue su curso desde
	// handle(). Los módulos vacían su ventana al alertar, así que el re-logueo de
	// esta línea queda acotado a un ciclo de umbral por IP, no por evento.
	//
	// EXCEPCIÓN: los bloqueos manuales (sendguard-ctl/API) son una decisión
	// explícita del administrador y no se vetan por país — en hosts con
	// allowed_countries=[PE] un atacante con IPs peruanas quedaría imbloqueable
	// y el ctl reportaría éxito sin haber hecho nada.
	if alert.Module != "manual" && e.isIPFromAllowedCountry(alert.IP) {
		country := e.cfg.GeoResolver.Country(baseIP(alert.IP))
		slog.Info("enforcement: IP de país permitido, bloqueo de firewall omitido",
			"ip", alert.IP, "country", country, "module", alert.Module)
		return
	}

	e.mu.Lock()
	if entry, exists := e.blockedIPs[alert.IP]; exists && time.Now().Before(entry.expiry) {
		e.mu.Unlock()
		slog.Info("enforcement: IP ya bloqueada, omitiendo duplicado", "ip", alert.IP, "expiry", entry.expiry.Format("15:04:05"))
		return
	}
	var expiry time.Time
	if banSecs > 0 {
		expiry = time.Now().Add(time.Duration(banSecs) * time.Second)
	} else {
		expiry = time.Now().Add(100 * 365 * 24 * time.Hour)
	}
	e.blockedIPs[alert.IP] = blockedIP{expiry: expiry, module: alert.Module}
	if _, ipnet, err := net.ParseCIDR(alert.IP); err == nil {
		e.blockedNets[alert.IP] = ipnet
	}
	e.mu.Unlock()

	// Persistir antes de ejecutar el comando para no perder el registro
	// si el proceso se reinicia inmediatamente después del ban.
	if e.cfg.Store != nil {
		if err := e.cfg.Store.SaveBan(alert.IP, alert.Module, expiry); err != nil {
			slog.Warn("enforcement: no se pudo persistir ban en SQLite", "ip", alert.IP, "error", err)
		}
	}

	// AbuseIPDB solo indexa IPs individuales; para CIDRs se omite la consulta.
	if e.cfg.AbuseIPDB != nil && !isCIDR(alert.IP) {
		if report, err := e.cfg.AbuseIPDB.Check(ctx, alert.IP); err == nil {
			if alert.Country == "" {
				alert.Country = report.CountryCode
			}
			alert.Reasons = append(alert.Reasons,
				fmt.Sprintf("AbuseIPDB score: %d/100 (%d reportes, país: %s)",
					report.AbuseScore, report.TotalReports, report.CountryCode))
		} else {
			slog.Warn("enforcement: AbuseIPDB consulta fallida", "ip", alert.IP, "error", err)
		}
	}

	if err := e.fw.Block(ctx, alert.IP, banSecs); err != nil {
		slog.Error("enforcement: fallo al bloquear IP", "ip", alert.IP, "error", err)
		e.mu.Lock()
		delete(e.blockedIPs, alert.IP)
		delete(e.blockedNets, alert.IP)
		e.mu.Unlock()
		if e.cfg.Store != nil {
			e.cfg.Store.DeleteBan(alert.IP)
		}
		return
	}

	e.blocksTotal.Add(1)
	slog.Info("enforcement: IP bloqueada",
		"ip", alert.IP,
		"ban_seconds", banSecs,
		"module", alert.Module,
	)

	// Agregar a la whitelist del engine para que deje de despachar eventos de esta IP.
	// Cuando el ban expire se quitará automáticamente (ver unbanExpired / Unblock).
	if e.cfg.Whitelist != nil {
		_ = e.cfg.Whitelist.AddIP(alert.IP)
	}
}

// suspendAccount suspende una cuenta Zimbra vía zmprov y bloquea la IP atacante si está presente.
func (e *Enforcer) suspendAccount(ctx context.Context, alert detection.Alert) {
	// Si la alerta tiene una IP de un país permitido, omitir la suspensión.
	// La notificación fluye igualmente desde handle().
	if e.isIPFromAllowedCountry(alert.IP) {
		country := e.cfg.GeoResolver.Country(alert.IP)
		slog.Info("enforcement: IP de país permitido, suspensión de cuenta omitida",
			"ip", alert.IP, "country", country, "account", alert.Account, "module", alert.Module)
		return
	}
	zmprov := e.cfg.ZmprovBin
	if zmprov == "" {
		zmprov = "/opt/zimbra/bin/zmprov"
	}
	cmd := exec.CommandContext(ctx, zmprov, "ma", alert.Account, "zimbraAccountStatus", "locked")
	out, err := cmd.CombinedOutput()
	if err != nil {
		slog.Error("enforcement: fallo al suspender cuenta",
			"account", alert.Account,
			"error", err,
			"output", string(out),
		)
		return
	}
	e.suspsTotal.Add(1)
	e.mu.Lock()
	e.suspendedAccts[alert.Account] = suspendedAcct{module: alert.Module, timestamp: time.Now()}
	e.mu.Unlock()
	slog.Info("enforcement: cuenta suspendida", "account", alert.Account, "module", alert.Module)

	// Avisar al propio usuario que su cuenta fue suspendida por compromiso.
	// Se envía DESPUÉS del lock: la cuenta locked sigue recibiendo correo pero
	// el atacante ya no puede autenticarse para leer o borrar el aviso.
	if e.cfg.UserNotifier != nil {
		if err := e.cfg.UserNotifier.NotifySuspendedUser(ctx, alert.Account, alert); err != nil {
			slog.Warn("enforcement: fallo al enviar aviso al usuario suspendido",
				"account", alert.Account, "error", err)
		} else {
			slog.Info("enforcement: aviso de suspensión enviado al usuario", "account", alert.Account)
		}
	}

	// Bloquear también la IP atacante en el firewall si está presente en la alerta.
	if alert.IP != "" {
		e.blockIPWithTTL(ctx, alert, e.cfg.BanSeconds)
	}
}

// isValidIP verifica que el string sea una dirección IPv4 válida.
func isValidIP(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.To4() != nil
}

// isCIDR retorna true si el target lleva máscara ("200.25.47.0/24").
func isCIDR(target string) bool {
	return strings.ContainsRune(target, '/')
}

// ValidBlockTarget acepta como objetivo de bloqueo una IPv4 ("1.2.3.4") o un
// CIDR IPv4 ("200.25.47.0/24"). Exportado para que la API valide el input
// antes de llamar a Block/Unblock.
func ValidBlockTarget(target string) bool {
	if isCIDR(target) {
		ip, _, err := net.ParseCIDR(target)
		return err == nil && ip.To4() != nil
	}
	return isValidIP(target)
}

// normalizeTarget canonicaliza un CIDR a su dirección de red
// ("200.25.47.5/24" → "200.25.47.0/24"); las IPs sueltas no cambian.
func normalizeTarget(target string) string {
	if !isCIDR(target) {
		return target
	}
	if _, ipnet, err := net.ParseCIDR(target); err == nil {
		return ipnet.String()
	}
	return target
}

// baseIP retorna la parte de dirección de un target: la IP misma, o la
// dirección base si es un CIDR. Útil para GeoIP y chequeos de red privada,
// que operan sobre direcciones individuales.
func baseIP(target string) string {
	if i := strings.IndexByte(target, '/'); i >= 0 {
		return target[:i]
	}
	return target
}

// isPrivateIP retorna true si la IP es privada (RFC 1918), loopback o link-local.
// Estas IPs jamás deben terminar en una regla de bloqueo del firewall.
func isPrivateIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	return parsed.IsPrivate() || parsed.IsLoopback() || parsed.IsLinkLocalUnicast() || parsed.IsUnspecified()
}

// BlockedIPInfo describe una IP bloqueada actualmente.
type BlockedIPInfo struct {
	IP     string
	Expiry time.Time
	Module string
}

// IsBlocked retorna true si la IP está actualmente bloqueada y el ban no ha
// expirado, ya sea por bloqueo directo o por pertenecer a un CIDR bloqueado.
// O(1) en el caso común (lookup exacto); el barrido de CIDRs solo ocurre si
// hay rangos bloqueados, que en la práctica son pocos (bloqueos manuales).
func (e *Enforcer) IsBlocked(ip string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := time.Now()
	if entry, ok := e.blockedIPs[ip]; ok && now.Before(entry.expiry) {
		return true
	}
	return e.blockingNetLocked(ip, now) != ""
}

// GetBlockedIP retorna los detalles de una IP bloqueada (directa o dentro de
// un CIDR bloqueado; en ese caso el campo IP de la respuesta es el CIDR).
// El segundo valor es false si la IP no está bloqueada o el ban expiró.
func (e *Enforcer) GetBlockedIP(ip string) (BlockedIPInfo, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := time.Now()
	if entry, ok := e.blockedIPs[ip]; ok && now.Before(entry.expiry) {
		return BlockedIPInfo{IP: ip, Expiry: entry.expiry, Module: entry.module}, true
	}
	if cidr := e.blockingNetLocked(ip, now); cidr != "" {
		entry := e.blockedIPs[cidr]
		return BlockedIPInfo{IP: cidr, Expiry: entry.expiry, Module: entry.module}, true
	}
	return BlockedIPInfo{}, false
}

// blockingNetLocked retorna el CIDR bloqueado (no expirado) que contiene a ip,
// o "" si ninguno. Debe llamarse con e.mu tomado.
func (e *Enforcer) blockingNetLocked(ip string, now time.Time) string {
	if len(e.blockedNets) == 0 {
		return ""
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	for cidr, ipnet := range e.blockedNets {
		entry, ok := e.blockedIPs[cidr]
		if ok && now.Before(entry.expiry) && ipnet.Contains(parsed) {
			return cidr
		}
	}
	return ""
}

// BlockedIPs retorna una copia de las IPs actualmente bloqueadas (no expiradas).
func (e *Enforcer) BlockedIPs() []BlockedIPInfo {
	now := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()

	result := make([]BlockedIPInfo, 0, len(e.blockedIPs))
	for ip, entry := range e.blockedIPs {
		if now.Before(entry.expiry) {
			result = append(result, BlockedIPInfo{
				IP:     ip,
				Expiry: entry.expiry,
				Module: entry.module,
			})
		}
	}
	return result
}

// SuspendedAccounts retorna una copia de las cuentas suspendidas en esta sesión.
func (e *Enforcer) SuspendedAccounts() []SuspendedAcctInfo {
	e.mu.Lock()
	defer e.mu.Unlock()
	result := make([]SuspendedAcctInfo, 0, len(e.suspendedAccts))
	for account, entry := range e.suspendedAccts {
		result = append(result, SuspendedAcctInfo{
			Account:   account,
			Module:    entry.module,
			Timestamp: entry.timestamp,
		})
	}
	return result
}

// Stats retorna los contadores acumulados de acciones ejecutadas.
func (e *Enforcer) Stats() EnforcerStats {
	return EnforcerStats{
		BlocksTotal:      e.blocksTotal.Load(),
		SuspensionsTotal: e.suspsTotal.Load(),
		RateLimitsTotal:  e.ratesTotal.Load(),
	}
}

// LoadExistingBans reconstruye el mapa interno de IPs baneadas al arrancar.
// Estrategia de dos fuentes (en orden de preferencia):
//  1. SQLite local — expirations exactas, restauración fiable tras reinicio.
//     Si la lectura tiene éxito (incluso con 0 bans), SQLite es autoritativo
//     y NO se consulta el firewall (0 bans = todos expiraron limpiamente).
//  2. Firewall     — fallback solo si SQLite no está configurado o devuelve error.
func (e *Enforcer) LoadExistingBans(ctx context.Context) {
	if e.cfg.Store != nil {
		if _, ok := e.loadBansFromStore(); ok {
			return // SQLite accesible — no reimportar reglas del firewall
		}
	}
	e.loadBansFromFirewalld(ctx)
}

// loadBansFromStore restaura bans desde SQLite.
// Retorna (número de IPs cargadas, true) en éxito, (0, false) si la lectura falla.
func (e *Enforcer) loadBansFromStore() (int, bool) {
	bans, err := e.cfg.Store.LoadActiveBans()
	if err != nil {
		slog.Warn("enforcement: no se pudo leer bans de SQLite, usando firewall", "error", err)
		return 0, false
	}

	loaded := 0
	e.mu.Lock()
	for _, b := range bans {
		if _, exists := e.blockedIPs[b.IP]; !exists {
			e.blockedIPs[b.IP] = blockedIP{expiry: b.ExpiresAt, module: b.Module}
			if _, ipnet, err := net.ParseCIDR(b.IP); err == nil {
				e.blockedNets[b.IP] = ipnet
			}
			loaded++
			if e.cfg.Whitelist != nil {
				_ = e.cfg.Whitelist.AddIP(b.IP)
			}
		}
	}
	e.mu.Unlock()

	if loaded > 0 {
		slog.Info("enforcement: bans restaurados desde SQLite", "count", loaded)
	}
	return loaded, true
}

// loadBansFromFirewalld restaura bans leyendo las reglas activas del firewall.
// Se usa como fallback cuando SQLite no está disponible.
// El nombre se mantiene por compatibilidad con los tests existentes.
func (e *Enforcer) loadBansFromFirewalld(ctx context.Context) {
	ips, err := e.fw.ListBlockedIPs(ctx)
	if err != nil {
		slog.Warn("enforcement: no se pudo leer reglas existentes del firewall", "error", err)
		return
	}

	now := time.Now()
	e.mu.Lock()
	loaded := 0
	for _, ip := range ips {
		if _, exists := e.blockedIPs[ip]; !exists {
			var expiry time.Time
			if e.cfg.BanSeconds > 0 {
				expiry = now.Add(time.Duration(e.cfg.BanSeconds) * time.Second)
			} else {
				expiry = now.Add(100 * 365 * 24 * time.Hour)
			}
			e.blockedIPs[ip] = blockedIP{expiry: expiry, module: "restored"}
			if _, ipnet, err := net.ParseCIDR(ip); err == nil {
				e.blockedNets[ip] = ipnet
			}
			loaded++
			if e.cfg.Whitelist != nil {
				_ = e.cfg.Whitelist.AddIP(ip)
			}
		}
	}
	e.mu.Unlock()

	if loaded > 0 {
		slog.Info("enforcement: reglas del firewall restauradas en memoria", "count", loaded)
	}
}

// Block bloquea manualmente una IP o un CIDR vía la API (sin pasar por el Engine).
// ttlOverride controla la duración:
//   - 0  → usa BanSeconds del config
//   - -1 → permanente (sin expiración)
//   - >0 → duración en segundos
func (e *Enforcer) Block(ctx context.Context, ip string, ttlOverride int) error {
	if !ValidBlockTarget(ip) {
		return fmt.Errorf("IP/CIDR inválido: %s", ip)
	}
	if isPrivateIP(baseIP(ip)) {
		return fmt.Errorf("IP/red privada o local, no se bloquea: %s", ip)
	}

	// Desacoplar del contexto del request HTTP: en hosts con firewalld lento
	// (miles de rich rules acumuladas) los dos firewall-cmd de un bloqueo
	// permanente superan el timeout del cliente, y CommandContext mataría el
	// segundo a mitad de camino dejando la regla runtime sin su par permanente.
	// El trabajo continúa con su propio límite aunque el cliente corte antes.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
	defer cancel()

	banSecs := e.cfg.BanSeconds
	switch {
	case ttlOverride == -1:
		banSecs = 0 // 0 en blockIP → permanente (100 años)
	case ttlOverride > 0:
		banSecs = ttlOverride
	}

	alert := detection.Alert{
		IP:        ip,
		Module:    "manual",
		Action:    detection.ActionBlockIP,
		Timestamp: time.Now(),
	}
	e.blockIPWithTTL(ctx, alert, banSecs)
	if e.cfg.AuditLog != nil {
		e.cfg.AuditLog.Log(ctx, alert)
	}
	return nil
}

// Unsuspend rehabilita una cuenta Zimbra suspendida vía zmprov y la elimina del registro interno.
func (e *Enforcer) Unsuspend(ctx context.Context, account string) error {
	if account == "" {
		return fmt.Errorf("cuenta vacía")
	}
	zmprov := e.cfg.ZmprovBin
	if zmprov == "" {
		zmprov = "/opt/zimbra/bin/zmprov"
	}
	cmd := exec.CommandContext(ctx, zmprov, "ma", account, "zimbraAccountStatus", "active")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("zmprov ma %s active: %w (output: %s)", account, err, strings.TrimSpace(string(out)))
	}
	e.mu.Lock()
	delete(e.suspendedAccts, account)
	e.mu.Unlock()
	slog.Info("enforcement: cuenta rehabilitada", "account", account)
	if e.cfg.AuditLog != nil {
		e.cfg.AuditLog.Log(ctx, detection.Alert{
			Account:   account,
			Module:    "manual",
			Action:    detection.ActionUnsuspendAcct,
			Timestamp: time.Now(),
		})
	}
	return nil
}

// Unblock elimina una IP o un CIDR del mapa interno y lo desbloquea en el firewall.
func (e *Enforcer) Unblock(ctx context.Context, ip string) error {
	if !ValidBlockTarget(ip) {
		return fmt.Errorf("IP/CIDR inválido: %s", ip)
	}
	ip = normalizeTarget(ip)

	// Mismo desacople que Block: las operaciones de firewall no deben morir
	// con el timeout del request HTTP (ver comentario en Block).
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
	defer cancel()

	e.mu.Lock()
	delete(e.blockedIPs, ip)
	delete(e.blockedNets, ip)
	e.mu.Unlock()

	if e.cfg.Store != nil {
		if err := e.cfg.Store.DeleteBan(ip); err != nil {
			slog.Warn("enforcement: no se pudo eliminar ban de SQLite", "ip", ip, "error", err)
		}
	}

	if e.cfg.Whitelist != nil {
		e.cfg.Whitelist.RemoveIP(ip)
	}

	if err := e.fw.Unblock(ctx, ip); err != nil {
		slog.Warn("enforcement: error al desbloquear en firewall", "ip", ip, "error", err)
	}

	slog.Info("enforcement: IP desbloqueada manualmente", "ip", ip)
	if e.cfg.AuditLog != nil {
		e.cfg.AuditLog.Log(ctx, detection.Alert{
			IP:        ip,
			Module:    "manual",
			Action:    detection.ActionUnblockIP,
			Timestamp: time.Now(),
		})
	}
	return nil
}

// isIPFromAllowedCountry retorna true si la IP no está vacía, GeoResolver está
// configurado, y el país de la IP aparece en AllowedCountries.
// Para CIDRs se evalúa la dirección base del rango.
func (e *Enforcer) isIPFromAllowedCountry(ip string) bool {
	if ip == "" || len(e.cfg.AllowedCountries) == 0 || e.cfg.GeoResolver == nil {
		return false
	}
	country := e.cfg.GeoResolver.Country(baseIP(ip))
	if country == "" {
		return false
	}
	upper := strings.ToUpper(country)
	for _, a := range e.cfg.AllowedCountries {
		if strings.ToUpper(a) == upper {
			return true
		}
	}
	return false
}
