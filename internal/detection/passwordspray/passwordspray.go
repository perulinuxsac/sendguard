// Package passwordspray detecta ataques de password spraying: una misma IP
// intentando autenticarse contra múltiples cuentas distintas con pocos intentos
// por cuenta (para evadir el umbral de auth_failed por IP).
//
// Complementa dist_brute_force (N IPs → 1 cuenta) detectando el patrón inverso:
// 1 IP → N cuentas. Es la técnica habitual en listas de credenciales filtradas.
//
// Cuando una IP falla contra MaxAccounts cuentas distintas en la ventana, se
// bloquea la IP inmediatamente (score 85 → ActionBlockIP).
//
// Fuente: eventos AuthFailed con IP y Account conocidos.
// Acción: ActionBlockIP (score 85).
package passwordspray

import (
	"fmt"
	"time"

	"github.com/perulinux/sendguard/internal/detection"
	"github.com/perulinux/sendguard/internal/event"
)

// Config agrupa los parámetros del módulo.
type Config struct {
	MaxAccounts int           // cuentas distintas fallidas desde la misma IP para bloquearla
	ScanTime    time.Duration // ventana de observación
}

type failRecord struct {
	ts      time.Time
	account string
}

// Module implementa detection.Module para la detección de password spraying.
// No es thread-safe: debe ser llamado exclusivamente desde el goroutine del Engine.
type Module struct {
	cfg       Config
	windows   map[string][]failRecord // IP → fallos recientes
	callCount int
}

const pruneEvery = 5_000

// New crea un módulo PasswordSpray con la configuración dada.
func New(cfg Config) *Module {
	return &Module{
		cfg:     cfg,
		windows: make(map[string][]failRecord),
	}
}

// Name implementa detection.Module.
func (m *Module) Name() string { return "password_spray" }

// Handle procesa un evento. Solo actúa sobre AuthFailed con IP y Account conocidos.
// Bloquea la IP cuando ha fallado contra MaxAccounts cuentas distintas en la ventana.
func (m *Module) Handle(ev event.Event) []detection.Alert {
	if ev.Type != event.AuthFailed || ev.IP == "" || ev.Account == "" {
		return nil
	}

	cutoff := ev.Timestamp.Add(-m.cfg.ScanTime)

	current := trimOld(m.windows[ev.IP], cutoff)
	current = append(current, failRecord{ts: ev.Timestamp, account: ev.Account})
	m.windows[ev.IP] = current

	m.callCount++
	if m.callCount >= pruneEvery {
		m.callCount = 0
		m.pruneExpired(cutoff)
	}

	accounts := uniqueAccounts(current)
	if len(accounts) < m.cfg.MaxAccounts {
		return nil
	}

	delete(m.windows, ev.IP)

	score := 85
	reason := fmt.Sprintf(
		"%d cuentas distintas atacadas desde %s en %s (umbral: %d) — password spraying",
		len(accounts), ev.IP, m.cfg.ScanTime.String(), m.cfg.MaxAccounts,
	)

	return []detection.Alert{{
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
	}}
}

func (m *Module) pruneExpired(cutoff time.Time) {
	for ip, records := range m.windows {
		if len(trimOld(records, cutoff)) == 0 {
			delete(m.windows, ip)
		}
	}
}

func uniqueAccounts(records []failRecord) []string {
	seen := make(map[string]struct{}, len(records))
	result := make([]string, 0, len(records))
	for _, r := range records {
		if _, ok := seen[r.account]; !ok {
			seen[r.account] = struct{}{}
			result = append(result, r.account)
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
