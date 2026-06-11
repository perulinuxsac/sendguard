// Package numbermessages detecta cuentas Zimbra que superan el volumen de envío
// a dominios EXTERNOS configurado en una ventana deslizante. Cuando una cuenta
// comprometida es utilizada para spam masivo, el módulo emite una alerta de
// suspensión antes de que el servidor quede en RBLs.
//
// Fuente de datos: eventos MessageSent (postfix/smtp, status=sent) con remitente
// autenticado correlacionado por el parser. Solo cuentan las entregas que salen
// del servidor: las entregas locales (postfix/lmtp a buzones Zimbra) y los saltos
// a infraestructura interna (amavis en loopback, MTAs en redes privadas) se
// ignoran — el correo interno entre cuentas del propio servidor no es spam saliente.
package numbermessages

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/perulinux/sendguard/internal/detection"
	"github.com/perulinux/sendguard/internal/event"
)

// Config agrupa los parámetros del módulo.
type Config struct {
	MaxMessages int           // número de mensajes externos en ventana para disparar alerta
	ScanTime    time.Duration // ventana de observación
}

// Module implementa detection.Module para la detección de volumen anómalo de envío.
// No es thread-safe: debe ser llamado exclusivamente desde el goroutine del Engine.
type Module struct {
	cfg       Config
	windows   map[string][]time.Time // account → timestamps de entregas externas en la ventana
	callCount int
}

const pruneEvery = 5_000

// New crea un módulo NumberMessages con la configuración dada.
func New(cfg Config) *Module {
	return &Module{
		cfg:     cfg,
		windows: make(map[string][]time.Time),
	}
}

// Name implementa detection.Module.
func (m *Module) Name() string { return "number_messages" }

// Handle procesa un evento. Solo actúa sobre MessageSent de remitente autenticado
// hacia un relay externo. Retorna una alerta con ActionSuspendAcct cuando la
// cuenta supera MaxMessages entregas externas en el período ScanTime.
func (m *Module) Handle(ev event.Event) []detection.Alert {
	if ev.Type != event.MessageSent || ev.Account == "" || !isExternalDelivery(ev) {
		return nil
	}

	cutoff := ev.Timestamp.Add(-m.cfg.ScanTime)

	current := trimOld(m.windows[ev.Account], cutoff)
	current = append(current, ev.Timestamp)
	m.windows[ev.Account] = current

	m.callCount++
	if m.callCount >= pruneEvery {
		m.callCount = 0
		m.pruneExpired(cutoff)
	}

	if len(current) < m.cfg.MaxMessages {
		return nil
	}

	// Umbral superado: borrar registro para que, si la cuenta es reactivada,
	// acumule desde cero sin disparar inmediatamente.
	delete(m.windows, ev.Account)

	score := 80
	reason := fmt.Sprintf(
		"%d mensajes a dominios externos enviados por %s en %s (umbral: %d)",
		len(current),
		ev.Account,
		m.cfg.ScanTime.String(),
		m.cfg.MaxMessages,
	)

	return []detection.Alert{{
		Module:    m.Name(),
		Score:     score,
		Severity:  detection.SeverityFromScore(score),
		Action:    detection.ActionSuspendAcct,
		Timestamp: ev.Timestamp,
		Server:    ev.Server,
		Account:   ev.Account,
		Domain:    ev.Domain,
		Reasons:   []string{reason},
	}}
}

// isExternalDelivery retorna true si la entrega salió del servidor hacia un
// dominio externo. Las entregas vía lmtp (buzones locales Zimbra) y los relays
// en loopback o redes privadas (amavis en 127.0.0.1:10024, MTAs internos) son
// tráfico dentro del servidor y no cuentan.
func isExternalDelivery(ev event.Event) bool {
	if !strings.HasSuffix(ev.Process, "/smtp") {
		return false // postfix/lmtp → buzón local
	}
	relay := ev.Extra["relay"]
	if relay == "" {
		return false
	}
	if strings.HasPrefix(relay, "localhost") {
		return false
	}
	// relay = "host[1.2.3.4]:25" — extraer la IP entre corchetes.
	if i := strings.IndexByte(relay, '['); i != -1 {
		if j := strings.IndexByte(relay[i+1:], ']'); j != -1 {
			if ip := net.ParseIP(relay[i+1 : i+1+j]); ip != nil {
				if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
					return false
				}
			}
		}
	}
	return true
}

// pruneExpired elimina del map las cuentas cuya ventana quedó vacía.
func (m *Module) pruneExpired(cutoff time.Time) {
	for account, times := range m.windows {
		if len(trimOld(times, cutoff)) == 0 {
			delete(m.windows, account)
		}
	}
}

// trimOld elimina timestamps anteriores a cutoff.
// Los timestamps se asumen ordenados cronológicamente.
func trimOld(times []time.Time, cutoff time.Time) []time.Time {
	i := 0
	for i < len(times) && times[i].Before(cutoff) {
		i++
	}
	return times[i:]
}
