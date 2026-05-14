// Package numbermessages detecta cuentas Zimbra que superan el volumen de envío
// configurado en una ventana deslizante. Cuando una cuenta compromentida es utilizada
// para spam masivo, el módulo emite una alerta de suspensión antes de que el servidor
// quede en RBLs.
//
// Fuente de datos: eventos QueueAccepted (postfix/qmgr from=<account>).
// Se usa qmgr porque es el punto más temprano donde conocemos el remitente y ya
// está en cola — no hay que esperar a la entrega efectiva. Los mensajes con
// remitente vacío (from=<>, típicos de NDRs/bounces) se ignoran.
package numbermessages

import (
	"fmt"
	"time"

	"github.com/perulinux/sendguard/internal/detection"
	"github.com/perulinux/sendguard/internal/event"
)

// Config agrupa los parámetros del módulo.
type Config struct {
	MaxMessages int           // número de mensajes en ventana para disparar alerta
	ScanTime    time.Duration // ventana de observación
}

// Module implementa detection.Module para la detección de volumen anómalo de envío.
// No es thread-safe: debe ser llamado exclusivamente desde el goroutine del Engine.
type Module struct {
	cfg       Config
	windows   map[string][]time.Time // account → timestamps de mensajes en la ventana
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

// Handle procesa un evento. Solo actúa sobre QueueAccepted con remitente conocido.
// Retorna una alerta con ActionSuspendAcct cuando la cuenta supera MaxMessages
// en el período ScanTime.
func (m *Module) Handle(ev event.Event) []detection.Alert {
	if ev.Type != event.QueueAccepted || ev.Account == "" {
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
		"%d mensajes enviados por %s en %s (umbral: %d)",
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
