package event

import "time"

// Type representa el tipo de evento extraído del maillog de Zimbra.
type Type string

const (
	AuthFailed      Type = "auth_failed"      // SASL login fallido
	AuthSuccess     Type = "auth_success"     // SASL login exitoso (submission autenticado)
	QueueAccepted   Type = "queue_accepted"   // qmgr: mensaje aceptado en cola (from=)
	MessageSent     Type = "message_sent"     // smtp: entrega exitosa (status=sent)
	MessageBounce   Type = "message_bounce"   // smtp: rebote (status=bounced)
	MessageDeferred Type = "message_deferred" // smtp: diferido (status=deferred)
)

// Event representa un evento de seguridad parseado desde el maillog.
type Event struct {
	Timestamp time.Time
	Type      Type

	// Identificación
	Server  string // hostname del servidor Zimbra
	Process string // ej: "postfix/smtpd", "postfix/qmgr"
	PID     int

	// Datos del evento
	QueueID string // ID de cola de Postfix (ej: "ABCDEF123456")
	Account string // cuenta afectada (ej: "user@domain.com")
	Domain  string // dominio extraído de Account
	IP      string // IP del cliente
	Country string // código de país (llenado por módulo GeoIP)

	// Extra: campos adicionales según el tipo de evento
	// AuthFailed: Extra["reason"] = motivo del fallo
	// QueueAccepted: Extra["size"] = tamaño del mensaje, Extra["nrcpt"] = destinatarios
	// MessageSent/Bounce/Deferred: Extra["to"] = destinatario, Extra["relay"] = relay
	Extra map[string]string

	Raw string // línea original del log
}
