// Package accounttakeover detecta el patrón completo de toma de control de cuenta:
// una IP acumula N fallos de autenticación contra una cuenta y luego consigue
// autenticarse con éxito desde esa misma IP (score 95), o bien la cuenta envía
// mensajes poco después de los fallos aunque el éxito venga de otra IP (score 80).
//
// Complementa auth_failed (que bloquea por intentos sin éxito) cubriendo el caso
// en que el atacante finalmente encuentra la contraseña correcta.
//
// Fuente: eventos AuthFailed + AuthSuccess + QueueAccepted.
// Acciones: ActionSuspendAcct (el enforcer también bloquea la IP atacante).
package accounttakeover

import (
	"fmt"
	"time"

	"github.com/perulinux/sendguard/internal/detection"
	"github.com/perulinux/sendguard/internal/event"
)

// Config agrupa los parámetros del módulo.
type Config struct {
	MinFailures  int           // fallos mínimos antes de marcar la cuenta como vigilada (default: 5)
	CorrelWindow time.Duration // ventana de correlación (default: 10 min)
}

type failRecord struct {
	ip string
	ts time.Time
}

type acctState struct {
	failures []failRecord // fallos recientes (ip, ts)
}

// Module detecta tomas de control de cuenta correlacionando fallos y éxitos de auth.
// No es thread-safe: debe ejecutarse exclusivamente desde el goroutine del Engine.
type Module struct {
	cfg       Config
	state     map[string]*acctState // account → estado de seguimiento
	callCount int
}

const pruneEvery = 5_000

// New crea un módulo AccountTakeover con la configuración dada.
func New(cfg Config) *Module {
	if cfg.MinFailures <= 0 {
		cfg.MinFailures = 5
	}
	if cfg.CorrelWindow <= 0 {
		cfg.CorrelWindow = 10 * time.Minute
	}
	return &Module{
		cfg:   cfg,
		state: make(map[string]*acctState),
	}
}

// Name implementa detection.Module.
func (m *Module) Name() string { return "account_takeover" }

// Handle procesa eventos de autenticación y envío de mensajes.
//
// Patrón 1 (score 95): AuthFailed × N desde IP X → AuthSuccess desde la misma IP X.
// El atacante encontró la contraseña. Muy alta confianza.
//
// Patrón 2 (score 80): AuthFailed × N para cuenta A → QueueAccepted para cuenta A.
// La cuenta envía mensajes justo después de múltiples fallos. Alta confianza.
func (m *Module) Handle(ev event.Event) []detection.Alert {
	m.callCount++
	if m.callCount >= pruneEvery {
		m.callCount = 0
		m.pruneExpired(ev.Timestamp)
	}

	switch ev.Type {
	case event.AuthFailed:
		m.recordFailure(ev)

	case event.AuthSuccess:
		return m.checkPattern1(ev)

	case event.QueueAccepted:
		return m.checkPattern2(ev)
	}
	return nil
}

// recordFailure registra un fallo de autenticación para la cuenta dada.
func (m *Module) recordFailure(ev event.Event) {
	if ev.IP == "" || ev.Account == "" {
		return
	}
	cutoff := ev.Timestamp.Add(-m.cfg.CorrelWindow)
	st := m.getOrCreate(ev.Account)
	st.failures = trimOld(st.failures, cutoff)
	st.failures = append(st.failures, failRecord{ip: ev.IP, ts: ev.Timestamp})
}

// checkPattern1 detecta: AuthFailed × N desde IP X → AuthSuccess desde la misma IP X.
// Es el indicador más fuerte — el atacante encontró la contraseña.
func (m *Module) checkPattern1(ev event.Event) []detection.Alert {
	if ev.Account == "" || ev.IP == "" {
		return nil
	}
	st, ok := m.state[ev.Account]
	if !ok {
		return nil
	}
	cutoff := ev.Timestamp.Add(-m.cfg.CorrelWindow)
	st.failures = trimOld(st.failures, cutoff)

	// Contar fallos de la misma IP que ahora autenticó con éxito.
	sameIPFailures := 0
	for _, f := range st.failures {
		if f.ip == ev.IP {
			sameIPFailures++
		}
	}
	if sameIPFailures < m.cfg.MinFailures {
		return nil
	}

	delete(m.state, ev.Account)

	score := 95
	reason := fmt.Sprintf(
		"cuenta %s: %d fallos de auth desde %s seguidos de auth exitoso desde la misma IP en %s — contraseña encontrada por fuerza bruta",
		ev.Account, sameIPFailures, ev.IP, m.cfg.CorrelWindow,
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

// checkPattern2 detecta: AuthFailed × N para cuenta → QueueAccepted para la misma cuenta.
// El mensaje podría venir de otra IP (webmail, app móvil) pero el patrón es sospechoso.
func (m *Module) checkPattern2(ev event.Event) []detection.Alert {
	if ev.Account == "" {
		return nil
	}
	st, ok := m.state[ev.Account]
	if !ok {
		return nil
	}
	cutoff := ev.Timestamp.Add(-m.cfg.CorrelWindow)
	st.failures = trimOld(st.failures, cutoff)

	if len(st.failures) < m.cfg.MinFailures {
		return nil
	}

	attackerIP := dominantIP(st.failures)
	totalFailures := len(st.failures)
	delete(m.state, ev.Account)

	score := 80
	reason := fmt.Sprintf(
		"cuenta %s aceptó mensajes en cola tras %d fallos de auth en %s — posible toma de control (IP con más intentos: %s)",
		ev.Account, totalFailures, m.cfg.CorrelWindow, attackerIP,
	)
	return []detection.Alert{{
		Module:    m.Name(),
		Score:     score,
		Severity:  detection.SeverityFromScore(score),
		Action:    detection.ActionSuspendAcct,
		Timestamp: ev.Timestamp,
		Server:    ev.Server,
		IP:        attackerIP,
		Account:   ev.Account,
		Domain:    ev.Domain,
		Reasons:   []string{reason},
	}}
}

func (m *Module) pruneExpired(now time.Time) {
	cutoff := now.Add(-m.cfg.CorrelWindow)
	for account, st := range m.state {
		st.failures = trimOld(st.failures, cutoff)
		if len(st.failures) == 0 {
			delete(m.state, account)
		}
	}
}

func (m *Module) getOrCreate(account string) *acctState {
	if st, ok := m.state[account]; ok {
		return st
	}
	st := &acctState{}
	m.state[account] = st
	return st
}

// dominantIP retorna la IP con más apariciones en los registros.
func dominantIP(records []failRecord) string {
	counts := make(map[string]int, len(records))
	for _, r := range records {
		counts[r.ip]++
	}
	var best string
	var max int
	for ip, n := range counts {
		if n > max || best == "" {
			max = n
			best = ip
		}
	}
	return best
}

func trimOld(records []failRecord, cutoff time.Time) []failRecord {
	i := 0
	for i < len(records) && records[i].ts.Before(cutoff) {
		i++
	}
	return records[i:]
}
