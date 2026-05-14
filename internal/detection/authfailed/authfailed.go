// Package authfailed detecta ataques de brute-force / credential stuffing sobre SASL.
// Cuenta los intentos fallidos por IP en una ventana deslizante y emite una alerta
// de bloqueo cuando se supera el umbral configurado.
package authfailed

import (
	"fmt"
	"time"

	"github.com/perulinux/sendguard/internal/detection"
	"github.com/perulinux/sendguard/internal/event"
)

// Config agrupa los parámetros del módulo.
type Config struct {
	MaxFailures int           // número de fallos para disparar alerta
	ScanTime    time.Duration // ventana de observación
}

// Module implementa detection.Module para la detección de brute-force SASL.
// No es thread-safe: debe ser llamado exclusivamente desde el goroutine del Engine.
//
// Gestión de memoria: IPs que acumulan fallos por debajo del umbral y no vuelven
// a intentarlo quedan en el map con entradas expiradas. Se hace una purga lazy
// cada pruneEvery eventos para liberar esa memoria.
type Module struct {
	cfg       Config
	windows   map[string][]time.Time // IP → timestamps de fallos dentro de la ventana
	callCount int                    // contador para la purga lazy
}

const pruneEvery = 5_000 // purgar entradas expiradas cada N eventos AuthFailed

// New crea un módulo AuthFailed con la configuración dada.
func New(cfg Config) *Module {
	return &Module{
		cfg:     cfg,
		windows: make(map[string][]time.Time),
	}
}

// Name implementa detection.Module.
func (m *Module) Name() string { return "auth_failed" }

// Handle procesa un evento. Solo actúa sobre event.AuthFailed.
// Retorna una alerta con ActionBlockIP cuando la IP supera MaxFailures en ScanTime.
func (m *Module) Handle(ev event.Event) []detection.Alert {
	if ev.Type != event.AuthFailed || ev.IP == "" {
		return nil
	}

	cutoff := ev.Timestamp.Add(-m.cfg.ScanTime)

	// Trimear entradas fuera de ventana y añadir el fallo actual.
	current := trimOld(m.windows[ev.IP], cutoff)
	current = append(current, ev.Timestamp)
	m.windows[ev.IP] = current

	// Purga lazy: eliminar IPs con ventana vacía acumuladas por ataques anteriores.
	m.callCount++
	if m.callCount >= pruneEvery {
		m.callCount = 0
		m.pruneExpired(cutoff)
	}

	if len(current) < m.cfg.MaxFailures {
		return nil
	}

	// Umbral superado. Borramos el registro para que intentos futuros
	// acumulen desde cero (el Enforcer controla el tiempo de baneo).
	delete(m.windows, ev.IP)

	reason := fmt.Sprintf(
		"%d fallos de autenticación SASL en %s",
		len(current),
		m.cfg.ScanTime.String(),
	)
	score := 60

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

// pruneExpired elimina del map las IPs cuya ventana quedó vacía tras el cutoff dado.
// Se llama periódicamente para evitar crecimiento ilimitado del map.
func (m *Module) pruneExpired(cutoff time.Time) {
	for ip, times := range m.windows {
		if len(trimOld(times, cutoff)) == 0 {
			delete(m.windows, ip)
		}
	}
}

// trimOld elimina del slice los timestamps anteriores a cutoff.
// Los timestamps se asumen ordenados cronológicamente (se insertan en orden).
func trimOld(times []time.Time, cutoff time.Time) []time.Time {
	i := 0
	for i < len(times) && times[i].Before(cutoff) {
		i++
	}
	// Reutilizamos el slice subyacente para evitar allocations.
	return times[i:]
}
