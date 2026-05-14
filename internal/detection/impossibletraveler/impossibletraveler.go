// Package impossibletraveler detecta inicios de sesión desde países distintos
// en un intervalo imposiblemente corto (viaje imposible geográfico).
//
// Si una cuenta autentica desde "PE" y 10 minutos después lo hace desde "CN",
// es muy probable que la cuenta esté comprometida. El módulo compara el país
// del último login conocido con el del evento actual; si difieren y el tiempo
// transcurrido es menor que WindowMinutes, emite una alerta de suspensión.
//
// La resolución GeoIP se delega a una interfaz (CountryLookup) para facilitar
// el testing sin necesidad de llamadas HTTP reales.
//
// Fuente: eventos AuthSuccess con IP y cuenta conocidas.
// Acción: suspensión de cuenta (ActionSuspendAcct), score 85.
package impossibletraveler

import (
	"fmt"
	"time"

	"github.com/perulinux/sendguard/internal/detection"
	"github.com/perulinux/sendguard/internal/event"
)

// CountryLookup resuelve una IP a un código de país ISO 3166-1 alpha-2.
// Retorna "" si no puede resolverse (IP privada, API caída, etc.).
type CountryLookup interface {
	Country(ip string) string
}

// Config agrupa los parámetros del módulo.
type Config struct {
	WindowMinutes int // ventana máxima en minutos para considerar el viaje como imposible
}

// loginRecord almacena el último inicio de sesión conocido de una cuenta.
type loginRecord struct {
	country   string
	ip        string
	timestamp time.Time
}

// Module implementa detection.Module para la detección de viaje imposible.
// No es thread-safe: debe ser llamado exclusivamente desde el goroutine del Engine.
type Module struct {
	cfg        Config
	geoip      CountryLookup
	lastLogins map[string]loginRecord // account → último login
}

// New crea un módulo ImpossibleTraveler con la configuración y resolver GeoIP dados.
func New(cfg Config, geoip CountryLookup) *Module {
	return &Module{
		cfg:        cfg,
		geoip:      geoip,
		lastLogins: make(map[string]loginRecord),
	}
}

// Name implementa detection.Module.
func (m *Module) Name() string { return "impossible_traveler" }

// Handle procesa un evento. Solo actúa sobre AuthSuccess con cuenta e IP conocidas.
// Emite una alerta si la cuenta inicia sesión desde un país distinto al del último
// login registrado, y el tiempo entre ambos logins es menor que WindowMinutes.
func (m *Module) Handle(ev event.Event) []detection.Alert {
	if ev.Type != event.AuthSuccess || ev.Account == "" || ev.IP == "" {
		return nil
	}

	country := m.geoip.Country(ev.IP)
	// Si no podemos resolver el país, ignoramos para evitar falsos positivos.
	if country == "" {
		return nil
	}

	current := loginRecord{
		country:   country,
		ip:        ev.IP,
		timestamp: ev.Timestamp,
	}

	prev, hasPrev := m.lastLogins[ev.Account]
	m.lastLogins[ev.Account] = current

	if !hasPrev {
		return nil
	}

	// Si el país no cambió, no hay viaje imposible.
	if prev.country == country {
		return nil
	}

	elapsed := ev.Timestamp.Sub(prev.timestamp)
	window := time.Duration(m.cfg.WindowMinutes) * time.Minute

	if elapsed < 0 {
		elapsed = -elapsed // eventos desordenados: usar valor absoluto
	}

	if elapsed >= window {
		return nil // tiempo suficiente para viajar entre países
	}

	score := 85
	reason := fmt.Sprintf(
		"login desde %s (%s) tras login desde %s (%s) hace %s (ventana: %dm)",
		country, ev.IP,
		prev.country, prev.ip,
		elapsed.Round(time.Second).String(),
		m.cfg.WindowMinutes,
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
