// Package domaindiscovery detecta ataques de credential spray dirigidos a cuentas
// de múltiples dominios distintos desde una misma IP.
//
// Un ataque de brute-force clásico (AuthFailed) apunta a una o pocas cuentas con
// muchos intentos. El credential spray es diferente: el atacante prueba contraseñas
// comunes contra listas de cuentas de muchas organizaciones distintas — baja densidad
// de fallos por dominio, alta diversidad de dominios atacados.
//
// Este módulo agrupa los eventos AuthFailed por IP y cuenta los dominios únicos de
// las cuentas intentadas. Si una IP falla contra cuentas de MaxDomains dominios
// distintos en ScanTime, la IP es probablemente parte de un botnet con listas de
// correos de múltiples clientes.
//
// Fuente: eventos AuthFailed con IP y Account conocidos.
// Acción: bloqueo de IP (ActionBlockIP), score 75.
package domaindiscovery

import (
	"fmt"
	"strings"
	"time"

	"github.com/perulinux/sendguard/internal/detection"
	"github.com/perulinux/sendguard/internal/event"
)

// Config agrupa los parámetros del módulo.
type Config struct {
	MaxDomains int           // dominios únicos atacados por una IP para disparar alerta
	ScanTime   time.Duration // ventana de observación (tumbling window por IP)
}

// ipState registra los dominios únicos atacados por una IP en la ventana activa.
type ipState struct {
	windowStart time.Time
	domains     map[string]struct{}
}

// Module implementa detection.Module para la detección de credential spray multi-dominio.
// No es thread-safe: debe ser llamado exclusivamente desde el goroutine del Engine.
type Module struct {
	cfg       Config
	states    map[string]*ipState // ip → estado de la ventana actual
	callCount int
}

const pruneEvery = 5_000

// New crea un módulo DomainDiscovery con la configuración dada.
func New(cfg Config) *Module {
	return &Module{
		cfg:    cfg,
		states: make(map[string]*ipState),
	}
}

// Name implementa detection.Module.
func (m *Module) Name() string { return "domain_discovery" }

// Handle procesa un evento. Solo actúa sobre AuthFailed con IP y Account conocidos.
// Retorna una alerta con ActionBlockIP cuando la IP ataca cuentas de MaxDomains
// dominios distintos en ScanTime.
func (m *Module) Handle(ev event.Event) []detection.Alert {
	if ev.Type != event.AuthFailed || ev.IP == "" || ev.Account == "" {
		return nil
	}

	domain := extractDomain(ev.Account)
	if domain == "" {
		return nil
	}

	m.callCount++
	if m.callCount >= pruneEvery {
		m.callCount = 0
		m.pruneExpired(ev.Timestamp)
	}

	state, ok := m.states[ev.IP]
	if !ok || ev.Timestamp.Sub(state.windowStart) >= m.cfg.ScanTime {
		// Primera vez o ventana expirada: nueva ventana limpia.
		state = &ipState{
			windowStart: ev.Timestamp,
			domains:     make(map[string]struct{}),
		}
		m.states[ev.IP] = state
	}

	state.domains[domain] = struct{}{}

	if len(state.domains) < m.cfg.MaxDomains {
		return nil
	}

	// Umbral superado: resetear para no alertar repetidamente por la misma IP.
	domainCount := len(state.domains)
	delete(m.states, ev.IP)

	score := 75
	reason := fmt.Sprintf(
		"IP %s intentó autenticación contra cuentas de %d dominios distintos en %s (umbral: %d)",
		ev.IP,
		domainCount,
		m.cfg.ScanTime.String(),
		m.cfg.MaxDomains,
	)

	return []detection.Alert{{
		Module:    m.Name(),
		Score:     score,
		Severity:  detection.SeverityFromScore(score),
		Action:    detection.ActionBlockIP,
		Timestamp: ev.Timestamp,
		Server:    ev.Server,
		IP:        ev.IP,
		Reasons:   []string{reason},
	}}
}

// pruneExpired elimina las IPs cuya ventana ha expirado.
func (m *Module) pruneExpired(now time.Time) {
	for ip, state := range m.states {
		if now.Sub(state.windowStart) >= m.cfg.ScanTime {
			delete(m.states, ip)
		}
	}
}

// extractDomain extrae el dominio de "user@domain.com". Retorna "" si no hay @.
func extractDomain(account string) string {
	if i := strings.LastIndex(account, "@"); i >= 0 {
		return account[i+1:]
	}
	return ""
}
