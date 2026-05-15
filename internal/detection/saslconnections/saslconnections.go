// Package saslconnections detecta abuso de conexiones SASL autenticadas.
//
// Dos señales de detección:
//
//  1. MaxUniqueIPs: N IPs distintas autentican como la misma cuenta en la ventana
//     → cuenta comprometida usada por botnet distribuido.
//     Acción: ActionSuspendAcct + ActionBlockIP por cada IP única (score 90).
//
//  2. Max: exceso de conexiones totales de la misma cuenta en la ventana
//     → botnet usando pocos nodos o una sola IP de forma intensiva.
//     Acción: ActionSuspendAcct (score 65).
//
// Fuente: eventos AuthSuccess (postfix/smtpd con sasl_username).
package saslconnections

import (
	"fmt"
	"time"

	"github.com/perulinux/sendguard/internal/detection"
	"github.com/perulinux/sendguard/internal/event"
)

// Config agrupa los parámetros del módulo.
type Config struct {
	Max          int           // conexiones autenticadas totales por cuenta en ventana (0 = deshabilitado)
	MaxUniqueIPs int           // IPs distintas por cuenta en ventana para bloquear (0 = deshabilitado)
	ScanTime     time.Duration // ventana de observación
}

// connection registra una conexión SASL autenticada.
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

	// Señal 1: múltiples IPs distintas autenticando la misma cuenta (toma de control distribuida).
	if m.cfg.MaxUniqueIPs > 0 {
		ips := uniqueIPs(current)
		if len(ips) >= m.cfg.MaxUniqueIPs {
			delete(m.windows, ev.Account)
			score := 90
			reason := fmt.Sprintf(
				"%d IPs distintas autenticaron como %s en %s (umbral: %d) — cuenta comprometida distribuida",
				len(ips), ev.Account, m.cfg.ScanTime.String(), m.cfg.MaxUniqueIPs,
			)
			alerts := make([]detection.Alert, 0, 1+len(ips))
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
			for _, ip := range ips {
				alerts = append(alerts, detection.Alert{
					Module:    m.Name(),
					Score:     score,
					Severity:  detection.SeverityFromScore(score),
					Action:    detection.ActionBlockIP,
					Timestamp: ev.Timestamp,
					Server:    ev.Server,
					IP:        ip,
					Account:   ev.Account,
					Domain:    ev.Domain,
					Reasons:   []string{reason},
				})
			}
			return alerts
		}
	}

	// Señal 2: exceso de conexiones totales (botnet concentrado).
	if m.cfg.Max > 0 && len(current) >= m.cfg.Max {
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
			IP:        ev.IP,
			Account:   ev.Account,
			Domain:    ev.Domain,
			Reasons:   []string{reason},
		}}
	}

	return nil
}

// pruneExpired elimina del map las cuentas cuya ventana quedó vacía.
func (m *Module) pruneExpired(cutoff time.Time) {
	for account, conns := range m.windows {
		if len(trimOld(conns, cutoff)) == 0 {
			delete(m.windows, account)
		}
	}
}

// uniqueIPs retorna la lista deduplicada de IPs no vacías en las conexiones.
func uniqueIPs(conns []connection) []string {
	seen := make(map[string]struct{}, len(conns))
	result := make([]string, 0, len(conns))
	for _, c := range conns {
		if c.ip != "" {
			if _, ok := seen[c.ip]; !ok {
				seen[c.ip] = struct{}{}
				result = append(result, c.ip)
			}
		}
	}
	return result
}

// trimOld elimina conexiones anteriores a cutoff.
func trimOld(conns []connection, cutoff time.Time) []connection {
	i := 0
	for i < len(conns) && conns[i].ts.Before(cutoff) {
		i++
	}
	return conns[i:]
}
