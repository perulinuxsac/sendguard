package detection

import "time"

// Action es la acción de contención que debe ejecutar el Enforcer.
type Action string

const (
	ActionBlockIP       Action = "block_ip"          // bloquear IP vía firewalld
	ActionUnblockIP     Action = "unblock_ip"        // desbloquear IP manualmente
	ActionSuspendAcct   Action = "suspend_account"   // zmprov zimbraAccountStatus locked
	ActionUnsuspendAcct Action = "unsuspend_account" // zmprov zimbraAccountStatus active
	ActionRateLimit     Action = "rate_limit"        // limitar envíos vía Postfix policy
	ActionPurgeQueue    Action = "purge_queue"       // purgar cola Postfix (infraestructura; no emitido automáticamente por ningún módulo)
	ActionNotifyOnly    Action = "notify_only"       // solo notificar, sin contención
)

// Severity mapea el score total a un nivel de respuesta.
type Severity int

const (
	SeverityLog       Severity = 0 // score 0-29:  solo log
	SeverityWarn      Severity = 1 // score 30-49: notificar admin
	SeverityRateLimit Severity = 2 // score 50-79: rate-limit + notificar
	SeveritySuspend   Severity = 3 // score 80+:   suspender + notificación urgente
)

// SeverityFromScore convierte un score numérico a Severity.
func SeverityFromScore(score int) Severity {
	switch {
	case score >= 80:
		return SeveritySuspend
	case score >= 50:
		return SeverityRateLimit
	case score >= 30:
		return SeverityWarn
	default:
		return SeverityLog
	}
}

// Alert representa una detección emitida por un módulo.
// El Enforcer decide qué acción ejecutar en base a Action y Severity.
type Alert struct {
	Module    string
	Score     int
	Severity  Severity
	Action    Action
	Timestamp time.Time

	// Contexto del evento que disparó la alerta
	Server  string
	IP      string
	Account string
	Domain  string
	Country string // código ISO 3166-1 alpha-2 (PE, US, …); vacío si no se resolvió

	Reasons []string // explicación legible de por qué se disparó
}
