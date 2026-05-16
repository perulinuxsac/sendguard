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
	"sync"
	"sync/atomic"
	"time"

	"github.com/perulinux/sendguard/internal/abuseipdb"
	"github.com/perulinux/sendguard/internal/audit"
	"github.com/perulinux/sendguard/internal/detection"
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

// Config agrupa los parámetros del Enforcer.
type Config struct {
	FirewallBackend string            // "firewalld" (RHEL) o "ufw" (Ubuntu); default: firewalld
	BanSeconds      int               // duración del bloqueo de IP (0 = permanente)
	ZmprovBin       string            // ruta completa a zmprov (default: /opt/zimbra/bin/zmprov)
	PostfixSbin     string            // /opt/zimbra/common/sbin — binarios de Postfix de Zimbra
	PostfixConf     string            // /opt/zimbra/common/conf — config de Postfix de Zimbra
	Notifier        notify.Notifier   // nil usa Noop (sin notificaciones)
	AbuseIPDB       *abuseipdb.Client // nil deshabilita la consulta de reputación
	AuditLog        *audit.Logger     // nil deshabilita el audit log
	Store           *store.Store      // nil deshabilita la persistencia local SQLite
	Forwarder       AlertForwarder    // nil deshabilita el StoreAndForward
	Whitelist       IPWhitelist       // nil deshabilita la sincronización con el engine
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
	cfg              Config
	fw               fw
	mu               sync.Mutex
	blockedIPs       map[string]blockedIP
	suspendedAccts   map[string]suspendedAcct
	blocksTotal      atomic.Int64
	suspsTotal       atomic.Int64
	ratesTotal       atomic.Int64
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
		suspendedAccts: make(map[string]suspendedAcct),
	}
}

// Run procesa alertas hasta que ctx sea cancelado.
// Para el backend ufw, lanza también un goroutine que desbloquea IPs expiradas
// (ufw no tiene --timeout nativo; el desbloqueo es responsabilidad del agente).
func (e *Enforcer) Run(ctx context.Context, alertCh <-chan detection.Alert) {
	if e.cfg.FirewallBackend == "ufw" && e.cfg.BanSeconds > 0 {
		go e.runUnbanLoop(ctx)
	}
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

// runUnbanLoop comprueba cada 30 s si hay bans expirados y los elimina del firewall.
// Solo se usa con el backend ufw (firewalld expira sus reglas con --timeout).
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
		}
	}
	e.mu.Unlock()

	for _, ip := range expired {
		if err := e.fw.Unblock(ctx, ip); err != nil {
			slog.Warn("enforcement: fallo al desbloquear IP expirada", "ip", ip, "error", err)
		} else {
			slog.Info("enforcement: ban expirado, IP desbloqueada", "ip", ip)
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
		if e.cfg.PostfixSbin == "" || e.cfg.PostfixConf == "" {
			slog.Warn("enforcement: rate_limit sin postfix_sbin/postfix_conf configurados, ignorando")
			return
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
			slog.Warn("enforcement: purge_queue sin postfix_sbin/postfix_conf configurados, ignorando")
			return
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

	if err := e.cfg.Notifier.Notify(ctx, alert); err != nil {
		slog.Warn("enforcement: error al notificar", "error", err, "module", alert.Module)
	}
}

// blockIP bloquea una IP usando el BanSeconds configurado globalmente.
func (e *Enforcer) blockIP(ctx context.Context, alert detection.Alert) {
	e.blockIPWithTTL(ctx, alert, e.cfg.BanSeconds)
}

// blockIPWithTTL bloquea una IP con un TTL explícito (0 = permanente).
func (e *Enforcer) blockIPWithTTL(ctx context.Context, alert detection.Alert, banSecs int) {
	if !isValidIP(alert.IP) {
		slog.Error("enforcement: IP inválida, no se bloqueará", "ip", alert.IP)
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
	e.mu.Unlock()

	// Persistir antes de ejecutar el comando para no perder el registro
	// si el proceso se reinicia inmediatamente después del ban.
	if e.cfg.Store != nil {
		if err := e.cfg.Store.SaveBan(alert.IP, alert.Module, expiry); err != nil {
			slog.Warn("enforcement: no se pudo persistir ban en SQLite", "ip", alert.IP, "error", err)
		}
	}

	if e.cfg.AbuseIPDB != nil {
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

// BlockedIPInfo describe una IP bloqueada actualmente.
type BlockedIPInfo struct {
	IP     string
	Expiry time.Time
	Module string
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
//  2. Firewall     — fallback si SQLite no está configurado o falla la lectura.
func (e *Enforcer) LoadExistingBans(ctx context.Context) {
	if e.cfg.Store != nil {
		if loaded := e.loadBansFromStore(); loaded > 0 {
			return
		}
	}
	e.loadBansFromFirewalld(ctx)
}

// loadBansFromStore restaura bans desde SQLite. Retorna el número de IPs cargadas.
func (e *Enforcer) loadBansFromStore() int {
	bans, err := e.cfg.Store.LoadActiveBans()
	if err != nil {
		slog.Warn("enforcement: no se pudo leer bans de SQLite, usando firewall", "error", err)
		return 0
	}

	loaded := 0
	e.mu.Lock()
	for _, b := range bans {
		if _, exists := e.blockedIPs[b.IP]; !exists {
			e.blockedIPs[b.IP] = blockedIP{expiry: b.ExpiresAt, module: b.Module}
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
	return loaded
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

// Block bloquea manualmente una IP vía la API (sin pasar por el Engine).
// ttlOverride controla la duración:
//   - 0  → usa BanSeconds del config
//   - -1 → permanente (sin expiración)
//   - >0 → duración en segundos
func (e *Enforcer) Block(ctx context.Context, ip string, ttlOverride int) error {
	if !isValidIP(ip) {
		return fmt.Errorf("IP inválida: %s", ip)
	}

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

// Unblock elimina una IP del mapa interno y la desbloquea en el firewall.
func (e *Enforcer) Unblock(ctx context.Context, ip string) error {
	if !isValidIP(ip) {
		return fmt.Errorf("IP inválida: %s", ip)
	}

	e.mu.Lock()
	delete(e.blockedIPs, ip)
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
