// Package queuemonitor detecta dominios destino que están rechazando o diferiendo
// sistemáticamente mensajes del servidor Zimbra.
//
// Cuando un dominio destino (ej: gmail.com, hotmail.com) empieza a diferir muchos
// mensajes, indica un problema de reputación: la IP del servidor probablemente está
// en una RBL, tiene un PTR incorrecto, o sus mensajes se clasifican como spam. La
// detección temprana permite notificar al administrador y purgar la cola antes de
// que el backlog crezca indefinidamente.
//
// Fuente: eventos MessageDeferred (postfix/smtp status=deferred), agrupados por
// dominio del destinatario (extraído de Extra["to"]).
// Acción: purga de cola (ActionPurgeQueue), score 70.
package queuemonitor

import (
	"fmt"
	"strings"
	"time"

	"github.com/perulinux/sendguard/internal/detection"
	"github.com/perulinux/sendguard/internal/event"
)

// Config agrupa los parámetros del módulo.
type Config struct {
	Threshold int           // número de deferrals al mismo dominio para disparar alerta
	ScanTime  time.Duration // ventana de observación
}

// Module implementa detection.Module para la detección de acumulación de deferrals
// hacia un mismo dominio destino. No es thread-safe.
type Module struct {
	cfg       Config
	windows   map[string][]time.Time // dominio destino → timestamps de deferrals
	callCount int
}

const pruneEvery = 5_000

// New crea un módulo QueueMonitor con la configuración dada.
func New(cfg Config) *Module {
	return &Module{
		cfg:     cfg,
		windows: make(map[string][]time.Time),
	}
}

// Name implementa detection.Module.
func (m *Module) Name() string { return "queue_monitor" }

// Handle procesa un evento. Solo actúa sobre MessageDeferred con destinatario conocido.
// Agrupa por dominio destino: cuando un dominio acumula Threshold deferrals en ScanTime,
// emite una alerta indicando un posible problema de reputación con ese destino.
func (m *Module) Handle(ev event.Event) []detection.Alert {
	if ev.Type != event.MessageDeferred {
		return nil
	}

	dest := ""
	if ev.Extra != nil {
		dest = ev.Extra["to"]
	}
	if dest == "" {
		return nil
	}

	domain := extractDomain(dest)
	if domain == "" {
		return nil
	}

	cutoff := ev.Timestamp.Add(-m.cfg.ScanTime)

	current := trimOld(m.windows[domain], cutoff)
	current = append(current, ev.Timestamp)
	m.windows[domain] = current

	m.callCount++
	if m.callCount >= pruneEvery {
		m.callCount = 0
		m.pruneExpired(cutoff)
	}

	if len(current) < m.cfg.Threshold {
		return nil
	}

	delete(m.windows, domain)

	score := 70
	reason := fmt.Sprintf(
		"%d mensajes diferidos hacia @%s en %s (umbral: %d) — posible problema de reputación",
		len(current),
		domain,
		m.cfg.ScanTime.String(),
		m.cfg.Threshold,
	)

	return []detection.Alert{{
		Module:    m.Name(),
		Score:     score,
		Severity:  detection.SeverityFromScore(score),
		Action:    detection.ActionPurgeQueue,
		Timestamp: ev.Timestamp,
		Server:    ev.Server,
		IP:        ev.IP,
		Domain:    domain,
		Reasons:   []string{reason},
	}}
}

// pruneExpired elimina del map los dominios cuya ventana quedó vacía.
func (m *Module) pruneExpired(cutoff time.Time) {
	for domain, times := range m.windows {
		if len(trimOld(times, cutoff)) == 0 {
			delete(m.windows, domain)
		}
	}
}

// trimOld elimina timestamps anteriores a cutoff.
func trimOld(times []time.Time, cutoff time.Time) []time.Time {
	i := 0
	for i < len(times) && times[i].Before(cutoff) {
		i++
	}
	return times[i:]
}

// extractDomain extrae el dominio de una dirección "user@domain.com".
func extractDomain(addr string) string {
	if i := strings.LastIndex(addr, "@"); i >= 0 {
		return addr[i+1:]
	}
	return ""
}
