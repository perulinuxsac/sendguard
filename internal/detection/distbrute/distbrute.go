// Package distbrute detecta ataques de fuerza bruta distribuida (credential stuffing):
// múltiples IPs distintas intentando autenticarse como la misma cuenta y fallando.
// Dado que cada IP falla una sola vez, el módulo auth_failed por IP no es efectivo.
//
// Cuando una cuenta recibe fallos de N IPs distintas en la ventana, se emite una
// alerta ActionNotifyOnly para que el administrador investigue. No se bloquean las
// IPs ni se suspende la cuenta automáticamente para evitar falsos positivos.
//
// Fuente: eventos AuthFailed con IP y Account conocidos.
// Acción: ActionNotifyOnly (score 55).
package distbrute

import (
	"fmt"
	"time"

	"github.com/perulinux/sendguard/internal/detection"
	"github.com/perulinux/sendguard/internal/event"
)

// Config agrupa los parámetros del módulo.
type Config struct {
	MaxIPs   int           // IPs distintas fallando contra la misma cuenta para notificar
	ScanTime time.Duration // ventana de observación
}

type failRecord struct {
	ts time.Time
	ip string
}

// Module implementa detection.Module para la detección de brute-force distribuido.
// No es thread-safe: debe ser llamado exclusivamente desde el goroutine del Engine.
type Module struct {
	cfg       Config
	windows   map[string][]failRecord // account → fallos recientes
	callCount int
}

const pruneEvery = 5_000

// New crea un módulo DistBrute con la configuración dada.
func New(cfg Config) *Module {
	return &Module{
		cfg:     cfg,
		windows: make(map[string][]failRecord),
	}
}

// Name implementa detection.Module.
func (m *Module) Name() string { return "dist_brute_force" }

// Handle procesa un evento. Solo actúa sobre AuthFailed con IP y Account conocidos.
// Emite ActionNotifyOnly cuando MaxIPs IPs distintas han fallado contra la misma cuenta.
func (m *Module) Handle(ev event.Event) []detection.Alert {
	if ev.Type != event.AuthFailed || ev.IP == "" || ev.Account == "" {
		return nil
	}

	cutoff := ev.Timestamp.Add(-m.cfg.ScanTime)

	current := trimOld(m.windows[ev.Account], cutoff)
	current = append(current, failRecord{ts: ev.Timestamp, ip: ev.IP})
	m.windows[ev.Account] = current

	m.callCount++
	if m.callCount >= pruneEvery {
		m.callCount = 0
		m.pruneExpired(cutoff)
	}

	ips := uniqueIPs(current)
	if len(ips) < m.cfg.MaxIPs {
		return nil
	}

	delete(m.windows, ev.Account)

	score := 55
	reason := fmt.Sprintf(
		"%d IPs distintas fallaron contra %s en %s (umbral: %d) — posible credential stuffing",
		len(ips), ev.Account, m.cfg.ScanTime.String(), m.cfg.MaxIPs,
	)

	return []detection.Alert{{
		Module:    m.Name(),
		Score:     score,
		Severity:  detection.SeverityFromScore(score),
		Action:    detection.ActionNotifyOnly,
		Timestamp: ev.Timestamp,
		Server:    ev.Server,
		IP:        ev.IP,
		Account:   ev.Account,
		Domain:    ev.Domain,
		Reasons:   []string{reason},
	}}
}

func (m *Module) pruneExpired(cutoff time.Time) {
	for account, records := range m.windows {
		if len(trimOld(records, cutoff)) == 0 {
			delete(m.windows, account)
		}
	}
}

func uniqueIPs(records []failRecord) []string {
	seen := make(map[string]struct{}, len(records))
	result := make([]string, 0, len(records))
	for _, r := range records {
		if _, ok := seen[r.ip]; !ok {
			seen[r.ip] = struct{}{}
			result = append(result, r.ip)
		}
	}
	return result
}

func trimOld(records []failRecord, cutoff time.Time) []failRecord {
	i := 0
	for i < len(records) && records[i].ts.Before(cutoff) {
		i++
	}
	return records[i:]
}
