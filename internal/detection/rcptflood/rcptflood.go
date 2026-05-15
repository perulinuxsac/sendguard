// Package rcptflood detecta sesiones autenticadas que añaden un número anómalo
// de destinatarios (RCPT TO) en poco tiempo — señal de una cuenta comprometida
// usada para spam masivo. Bloquea la IP origen y suspende la cuenta.
//
// Fuente de datos: eventos RecipientAdded (postfix/smtps/smtpd filter: RCPT from).
package rcptflood

import (
	"fmt"
	"time"

	"github.com/perulinux/sendguard/internal/detection"
	"github.com/perulinux/sendguard/internal/event"
)

// Config agrupa los parámetros del módulo.
type Config struct {
	MaxRecipients int           // destinatarios por IP en la ventana para disparar alerta
	ScanTime      time.Duration // ventana de observación
}

// Module implementa detection.Module para la detección de flood de destinatarios.
// No es thread-safe: debe ser llamado exclusivamente desde el goroutine del Engine.
type Module struct {
	cfg       Config
	windows   map[string][]time.Time // ip → timestamps de cada RCPT en ventana
	callCount int
}

const pruneEvery = 5_000

// New crea un módulo RcptFlood con la configuración dada.
func New(cfg Config) *Module {
	return &Module{
		cfg:     cfg,
		windows: make(map[string][]time.Time),
	}
}

// Name implementa detection.Module.
func (m *Module) Name() string { return "rcpt_flood" }

// Handle procesa un evento. Solo actúa sobre RecipientAdded con IP conocida.
// Cuando la IP supera MaxRecipients en ScanTime emite dos alertas:
// ActionBlockIP (para el enforcer de firewall) y ActionSuspendAcct (zmprov).
func (m *Module) Handle(ev event.Event) []detection.Alert {
	if ev.Type != event.RecipientAdded || ev.IP == "" {
		return nil
	}

	cutoff := ev.Timestamp.Add(-m.cfg.ScanTime)

	current := trimOld(m.windows[ev.IP], cutoff)
	current = append(current, ev.Timestamp)
	m.windows[ev.IP] = current

	m.callCount++
	if m.callCount >= pruneEvery {
		m.callCount = 0
		m.pruneExpired(cutoff)
	}

	if len(current) < m.cfg.MaxRecipients {
		return nil
	}

	delete(m.windows, ev.IP)

	score := 90
	reason := fmt.Sprintf(
		"%d destinatarios desde %s (cuenta: %s) en %s (umbral: %d)",
		len(current), ev.IP, ev.Account, m.cfg.ScanTime.String(), m.cfg.MaxRecipients,
	)

	alerts := []detection.Alert{
		{
			Module:    m.Name(),
			Score:     score,
			Severity:  detection.SeverityFromScore(score),
			Action:    detection.ActionBlockIP,
			Timestamp: ev.Timestamp,
			Server:    ev.Server,
			IP:        ev.IP,
			Account:   ev.Account,
			Domain:    ev.Domain,
			Reasons:   []string{reason},
		},
	}

	if ev.Account != "" {
		alerts = append(alerts, detection.Alert{
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
		})
	}

	return alerts
}

func (m *Module) pruneExpired(cutoff time.Time) {
	for ip, times := range m.windows {
		if len(trimOld(times, cutoff)) == 0 {
			delete(m.windows, ip)
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
