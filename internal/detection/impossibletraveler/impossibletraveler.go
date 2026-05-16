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
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/perulinux/sendguard/internal/detection"
	"github.com/perulinux/sendguard/internal/event"
)

// CountryLookup resuelve una IP a un código de país ISO 3166-1 alpha-2.
// Retorna "" si no puede resolverse (IP privada, API caída, etc.).
type CountryLookup interface {
	Country(ip string) string
}

// OrgLookup es una extensión opcional de CountryLookup para obtener la organización/ASN
// de una IP (ej: "AS8075 MICROSOFT-CORP-MSN-AS-BLOCK"). Si el resolver no la implementa
// la detección por org simplemente no aplica.
type OrgLookup interface {
	Org(ip string) string
}

// Config agrupa los parámetros del módulo.
type Config struct {
	WindowMinutes    int      // ventana máxima en minutos para considerar el viaje como imposible
	AllowedCountries []string // países en whitelist; si ambos países están aquí no se alerta
	TrustedCIDRs     []string // rangos de proxies conocidos (Outlook, Gmail, etc.) — se ignoran por completo
	TrustedOrgs      []string // nombres de org/ASN conocidos (ej: "Microsoft", "Google") — detectados via ipinfo.io
}

func (c Config) isAllowed(country string) bool {
	for _, a := range c.AllowedCountries {
		if a == country {
			return true
		}
	}
	return false
}

// parseCIDRs convierte los strings de TrustedCIDRs a *net.IPNet, descartando los inválidos.
func parseCIDRs(cidrs []string) []*net.IPNet {
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			slog.Warn("impossible_traveler: CIDR inválido ignorado", "cidr", cidr)
			continue
		}
		nets = append(nets, ipnet)
	}
	return nets
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
	cfg          Config
	geoip        CountryLookup
	lastLogins   map[string]loginRecord // account → último login
	trustedNets  []*net.IPNet           // rangos de proxies conocidos (parseados al inicio)
}

// New crea un módulo ImpossibleTraveler con la configuración y resolver GeoIP dados.
func New(cfg Config, geoip CountryLookup) *Module {
	return &Module{
		cfg:         cfg,
		geoip:       geoip,
		lastLogins:  make(map[string]loginRecord),
		trustedNets: parseCIDRs(cfg.TrustedCIDRs),
	}
}

// isTrustedOrg retorna true si la org de la IP contiene alguno de los nombres configurados.
// Requiere que el resolver implemente OrgLookup; si no, siempre retorna false.
func (m *Module) isTrustedOrg(ip string) bool {
	if len(m.cfg.TrustedOrgs) == 0 {
		return false
	}
	ol, ok := m.geoip.(OrgLookup)
	if !ok {
		return false
	}
	org := strings.ToLower(ol.Org(ip))
	if org == "" {
		return false
	}
	for _, name := range m.cfg.TrustedOrgs {
		if strings.Contains(org, strings.ToLower(name)) {
			return true
		}
	}
	return false
}

// isTrustedProxy retorna true si la IP pertenece a un rango de proxy conocido.
func (m *Module) isTrustedProxy(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, ipnet := range m.trustedNets {
		if ipnet.Contains(parsed) {
			return true
		}
	}
	return false
}

// Name implementa detection.Module.
func (m *Module) Name() string { return "impossible_traveler" }

// Handle procesa un evento. Solo actúa sobre AuthSuccess con cuenta e IP conocidas.
// Emite una alerta si la cuenta inicia sesión desde un país distinto al del último
// login registrado, y el tiempo entre ambos logins es menor que WindowMinutes.
// Los logins desde proxies conocidos (Outlook Mobile, Gmail, etc.) se ignoran por completo:
// no actualizan la ubicación del usuario ni disparan alertas.
func (m *Module) Handle(ev event.Event) []detection.Alert {
	if ev.Type != event.AuthSuccess || ev.Account == "" || ev.IP == "" {
		return nil
	}

	// Ignorar proxies conocidos (CIDR o nombre de organización) — no actualizar ubicación ni comparar.
	if m.isTrustedProxy(ev.IP) || m.isTrustedOrg(ev.IP) {
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

	// Si ambos países están en la whitelist no hay anomalía (ej: PE + ES ambos permitidos).
	if m.cfg.isAllowed(prev.country) && m.cfg.isAllowed(country) {
		return nil
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
		Country:   country,
		Reasons:   []string{reason},
	}}
}
