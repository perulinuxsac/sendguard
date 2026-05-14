// Package saslconnections detecta abuso de conexiones SASL autenticadas.
//
// Un usuario legítimo rara vez abre más de 1-2 sesiones SMTP autenticadas
// simultáneas. Un botnet usando una cuenta comprometida generará muchas
// conexiones autenticadas en paralelo desde IPs distintas (credential stuffing
// con éxito distribuido). Este módulo detecta ese patrón contando eventos
// AuthSuccess por cuenta en una ventana deslizante.
//
// Fuente: eventos AuthSuccess (postfix/smtpd con sasl_username).
// Acción: suspensión de cuenta (ActionSuspendAcct), score 65.
package saslconnections

import (
	"fmt"
	"time"

	"github.com/perulinux/sendguard/internal/detection"
	"github.com/perulinux/sendguard/internal/event"
)

// Config agrupa los parámetros del módulo.
type Config struct {
	Max      int           // número de conexiones SASL autenticadas en la ventana para disparar alerta
	ScanTime time.Duration // ventana de observación
}

// connection registra una conexión SASL autenticada con la IP de origen,
// útil para incluirla en el contexto de la alerta.
type connection struct {
	ts time.Time
	ip string
}

// Module implementa detection.Module para la detección de abuso de conexiones SASL.
// No es thread-safe: debe ser llamado exclusivamente desde el goroutine del Engine.
type Module struct {
	cfg       Config
	windows   map[string][]connection // account → conexiones recientes
	callCount int
}

const pruneEvery = 5_000

// New crea un módulo SaslConnections con la configuración dada.
func New(cfg Config) *Module {
	return &Module{
		cfg:     cfg,
		windows: make(map[string][]connection),
	}
}

// Name implementa detection.Module.
func (m *Module) Name() string { return "sasl_connections" }

// Handle procesa un evento. Solo actúa sobre AuthSuccess con cuenta conocida.
// Retorna una alerta con ActionSuspendAcct cuando la cuenta supera Max conexiones
// autenticadas en ScanTime.
func (m *Module) Handle(ev event.Event) []detection.Alert {
	if ev.Type != event.AuthSuccess || ev.Account == "" {
		return nil
	}

	cutoff := ev.Timestamp.Add(-m.cfg.ScanTime)

	current := trimOld(m.windows[ev.Account], cutoff)
	current = append(current, connection{ts: ev.Timestamp, ip: ev.IP})
	m.windows[ev.Account] = current

	m.callCount++
	if m.callCount >= pruneEvery {
		m.callCount = 0
		m.pruneExpired(cutoff)
	}

	if len(current) < m.cfg.Max {
		return nil
	}

	// Umbral superado. Borramos el registro para acumular desde cero
	// si la cuenta es reactivada tras la suspensión.
	delete(m.windows, ev.Account)

	score := 65
	reason := fmt.Sprintf(
		"%d conexiones SASL autenticadas de %s en %s (umbral: %d)",
		len(current),
		ev.Account,
		m.cfg.ScanTime.String(),
		m.cfg.Max,
	)

	return []detection.Alert{{
		Module:    m.Name(),
		Score:     score,
		Severity:  detection.SeverityFromScore(score),
		Action:    detection.ActionSuspendAcct,
		Timestamp: ev.Timestamp,
		Server:    ev.Server,
		IP:        ev.IP, // IP de la conexión que cruzó el umbral
		Account:   ev.Account,
		Domain:    ev.Domain,
		Reasons:   []string{reason},
	}}
}

// pruneExpired elimina del map las cuentas cuya ventana quedó vacía.
func (m *Module) pruneExpired(cutoff time.Time) {
	for account, conns := range m.windows {
		if len(trimOld(conns, cutoff)) == 0 {
			delete(m.windows, account)
		}
	}
}

// trimOld elimina conexiones anteriores a cutoff.
// Las conexiones se asumen ordenadas cronológicamente.
func trimOld(conns []connection, cutoff time.Time) []connection {
	i := 0
	for i < len(conns) && conns[i].ts.Before(cutoff) {
		i++
	}
	return conns[i:]
}
