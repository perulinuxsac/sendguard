package detection

import "time"

// Action es la acción de contención que debe ejecutar el Enforcer.
type Action string

const (
	ActionBlockIP       Action = "block_ip"          // bloquear IP vía firewall (ipset/ufw)
	ActionUnblockIP     Action = "unblock_ip"        // desbloquear IP manualmente
	ActionSuspendAcct   Action = "suspend_account"   // zmprov zimbraAccountStatus locked
	ActionUnsuspendAcct Action = "unsuspend_account" // zmprov zimbraAccountStatus active
	ActionNotifyOnly    Action = "notify_only"       // solo notificar, sin contención
)

// Severity mapea el score total a un nivel de respuesta.
type Severity int

const (
	SeverityLog     Severity = 0 // score 0-29:  solo log
	SeverityWarn    Severity = 1 // score 30-49: notificar admin
	SeverityHigh    Severity = 2 // score 50-79: notificación prioritaria
	SeveritySuspend Severity = 3 // score 80+:   suspender + notificación urgente
)

// SeverityFromScore convierte un score numérico a Severity.
func SeverityFromScore(score int) Severity {
	switch {
	case score >= 80:
		return SeveritySuspend
	case score >= 50:
		return SeverityHigh
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

	// Resultado real de la contención, lo completa el Enforcer (no los módulos).
	// Las notificaciones se arman con esto y no con la acción pedida: un
	// suspend_account puede terminar omitido (país permitido), ya aplicado o
	// fallido, y el aviso debe decirlo.
	Outcome       Outcome  // vacío = sin contención (notify_only) o no evaluado
	OutcomeDetail string   // motivo de la omisión o error del fallo
	Effects       []Effect // lo que el enforcer hizo (o intentó), en orden
}

// Outcome resume qué pasó con la contención pedida por la alerta.
type Outcome string

const (
	OutcomeApplied Outcome = "applied" // se ejecutó
	OutcomeSkipped Outcome = "skipped" // omitida a propósito (país permitido, IP privada)
	OutcomeAlready Outcome = "already" // ya estaba aplicada (cuenta ya suspendida, IP ya bloqueada)
	OutcomeFailed  Outcome = "failed"  // se intentó y falló
)

// Effect es un paso concreto ejecutado por el enforcer para una alerta
// (suspender la cuenta, bloquear la IP, avisar al usuario…).
type Effect struct {
	Outcome Outcome
	Text    string // descripción legible: "Cuenta bloqueada en Zimbra", "IP 1.2.3.4 bloqueada 1 h"
}
