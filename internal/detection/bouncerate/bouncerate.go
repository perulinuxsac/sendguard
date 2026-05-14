// Package bouncerate detecta cuentas que generan un volumen anormal de rebotes (NDRs).
// Un pico de bounces en ventana corta es señal clara de cuenta comprometida enviando
// spam a listas de correo inválidas o direcciones inexistentes.
package bouncerate

import (
	"fmt"
	"time"

	"github.com/perulinux/sendguard/internal/detection"
	"github.com/perulinux/sendguard/internal/event"
)

// Config agrupa los parámetros del módulo.
type Config struct {
	MaxBounces int           // número de rebotes para disparar alerta
	ScanTime   time.Duration // ventana de observación
}

// Module implementa detection.Module para la detección de bounce rate anormal.
// No es thread-safe: debe ser llamado exclusivamente desde el goroutine del Engine.
type Module struct {
	cfg       Config
	windows   map[string][]time.Time // cuenta → timestamps de bounces dentro de la ventana
	callCount int
}

const pruneEvery = 2_000

// New crea un módulo BounceRate con la configuración dada.
func New(cfg Config) *Module {
	return &Module{
		cfg:     cfg,
		windows: make(map[string][]time.Time),
	}
}

// Name implementa detection.Module.
func (m *Module) Name() string { return "bounce_rate" }

// Handle procesa un evento. Solo actúa sobre event.MessageBounce con Account no vacía.
// Emite ActionSuspendAcct cuando la cuenta supera MaxBounces en ScanTime.
func (m *Module) Handle(ev event.Event) []detection.Alert {
	if ev.Type != event.MessageBounce || ev.Account == "" {
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

	if len(current) < m.cfg.MaxBounces {
		return nil
	}

	delete(m.windows, ev.Account)

	reason := fmt.Sprintf(
		"%d rebotes en %s — posible cuenta comprometida enviando spam",
		len(current),
		m.cfg.ScanTime.String(),
	)
	score := 85

	return []detection.Alert{{
		Module:    m.Name(),
		Score:     score,
		Severity:  detection.SeverityFromScore(score),
		Action:    detection.ActionSuspendAcct,
		Timestamp: ev.Timestamp,
		Server:    ev.Server,
		IP:        ev.IP,
		Account:   ev.Account,
		Domain:    ev.Domain,
		Reasons:   []string{reason},
	}}
}

func (m *Module) pruneExpired(cutoff time.Time) {
	for account, times := range m.windows {
		if len(trimOld(times, cutoff)) == 0 {
			delete(m.windows, account)
		}
	}
}

func trimOld(times []time.Time, cutoff time.Time) []time.Time {
	i := 0
	for i < len(times) && times[i].Before(cutoff) {
		i++
	}
	return times[i:]
}
