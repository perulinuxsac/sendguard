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
// Fuente: eventos AuthSuccess de Postfix (smtpd/submission con sasl_username).
// Los logins IMAP/POP3/SOAP de mailbox.log se ignoran: un Outlook con varias
// sesiones IMAP o un móvil que consulta POP3 cada minuto superan el umbral de
// conexiones sin que haya abuso de envío.
//
// País de la alerta: el enforcer omite la suspensión si la IP de la alerta es
// de un país permitido. Con varias IPs en la ventana, la alerta lleva la
// primera IP de un país NO permitido (si hay Geo configurado); así no depende
// de cuál login cruzó el umbral —que puede ser el del usuario legítimo—.
package saslconnections

import (
	"fmt"
	"strings"
	"time"

	"github.com/perulinux/sendguard/internal/detection"
	"github.com/perulinux/sendguard/internal/event"
)

// CountryLookup resuelve una IP a su código de país ISO (mayúsculas).
type CountryLookup interface {
	Country(ip string) string
}

// Config agrupa los parámetros del módulo.
type Config struct {
	Max              int           // conexiones autenticadas totales por cuenta en ventana (0 = deshabilitado)
	MaxUniqueIPs     int           // IPs distintas por cuenta en ventana para bloquear (0 = deshabilitado)
	ScanTime         time.Duration // ventana de observación
	AllowedCountries []string      // países permitidos (mismos que el enforcer); vacío = sin selección por país
	Geo              CountryLookup // nil = la alerta lleva la IP del evento que cruzó el umbral
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
	if ev.Type != event.AuthSuccess || ev.Account == "" || isMailboxProtocol(ev.Process) {
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
				IP:        m.targetIP(ips, ev.IP),
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
		target := m.targetIP(uniqueIPs(current), ev.IP)
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
			IP:        target,
			Account:   ev.Account,
			Domain:    ev.Domain,
			Reasons:   []string{reason},
		}}
	}

	return nil
}

// isMailboxProtocol indica si el evento viene de mailbox.log (IMAP/POP3/SOAP/
// account) en lugar de Postfix.
func isMailboxProtocol(process string) bool {
	switch strings.ToLower(process) {
	case "imap", "pop3", "soap", "account":
		return true
	}
	return false
}

// targetIP elige la IP de la alerta de suspensión: la primera de un país no
// permitido (o de país desconocido) entre las de la ventana. Si todas son de
// países permitidos, o no hay Geo configurado, usa fallback (la IP del evento).
func (m *Module) targetIP(ips []string, fallback string) string {
	if m.cfg.Geo == nil || len(m.cfg.AllowedCountries) == 0 {
		return fallback
	}
	for _, ip := range ips {
		if !m.allowed(m.cfg.Geo.Country(ip)) {
			return ip
		}
	}
	return fallback
}

func (m *Module) allowed(country string) bool {
	if country == "" {
		return false
	}
	for _, a := range m.cfg.AllowedCountries {
		if strings.EqualFold(strings.TrimSpace(a), country) {
			return true
		}
	}
	return false
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
