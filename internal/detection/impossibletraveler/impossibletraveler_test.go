package impossibletraveler_test

import (
	"strings"
	"testing"
	"time"

	"github.com/perulinux/sendguard/internal/detection"
	"github.com/perulinux/sendguard/internal/detection/impossibletraveler"
	"github.com/perulinux/sendguard/internal/event"
)

// mockGeoIP implementa CountryLookup y OrgLookup para tests.
type mockGeoIP struct {
	countries map[string]string
	orgs      map[string]string
}

func (m *mockGeoIP) Country(ip string) string { return m.countries[ip] }
func (m *mockGeoIP) Org(ip string) string     { return m.orgs[ip] }

var defaultCfg = impossibletraveler.Config{
	WindowMinutes: 60,
}

func authEvent(account, ip string, ts time.Time) event.Event {
	return event.Event{
		Type:      event.AuthSuccess,
		Account:   account,
		Domain:    domainOf(account),
		IP:        ip,
		Server:    "mail01",
		Timestamp: ts,
	}
}

func domainOf(account string) string {
	for i := len(account) - 1; i >= 0; i-- {
		if account[i] == '@' {
			return account[i+1:]
		}
	}
	return account
}

// geoip con dos IPs de países distintos para probar viaje imposible.
func twoCountryGeoIP() *mockGeoIP {
	return &mockGeoIP{
		countries: map[string]string{"1.1.1.1": "PE", "2.2.2.2": "CN"},
		orgs:      map[string]string{},
	}
}

func TestFirstLoginNoAlert(t *testing.T) {
	m := impossibletraveler.New(defaultCfg, twoCountryGeoIP())
	now := time.Now()

	alerts := m.Handle(authEvent("user@domain.com", "1.1.1.1", now))
	if len(alerts) != 0 {
		t.Fatal("el primer login no debe generar alerta")
	}
}

func TestSameCountryNoAlert(t *testing.T) {
	geo := &mockGeoIP{countries: map[string]string{
		"1.1.1.1": "PE",
		"1.1.1.2": "PE",
	}}
	m := impossibletraveler.New(defaultCfg, geo)
	now := time.Now()

	m.Handle(authEvent("user@domain.com", "1.1.1.1", now))
	alerts := m.Handle(authEvent("user@domain.com", "1.1.1.2", now.Add(5*time.Minute)))
	if len(alerts) != 0 {
		t.Fatal("mismo país no debe generar alerta")
	}
}

func TestImpossibleTravelerDetected(t *testing.T) {
	m := impossibletraveler.New(defaultCfg, twoCountryGeoIP())
	now := time.Now()

	m.Handle(authEvent("user@domain.com", "1.1.1.1", now))
	alerts := m.Handle(authEvent("user@domain.com", "2.2.2.2", now.Add(10*time.Minute)))

	if len(alerts) != 1 {
		t.Fatalf("se esperaba 1 alerta de viaje imposible, got %d", len(alerts))
	}
	a := alerts[0]
	if a.Action != detection.ActionSuspendAcct {
		t.Errorf("Action: got %q, want ActionSuspendAcct", a.Action)
	}
	if a.Score != 85 {
		t.Errorf("Score: got %d, want 85", a.Score)
	}
	if a.Severity != detection.SeveritySuspend {
		t.Errorf("Severity: got %d, want SeveritySuspend(%d)", a.Severity, detection.SeveritySuspend)
	}
	if a.Module != "impossible_traveler" {
		t.Errorf("Module: got %q, want %q", a.Module, "impossible_traveler")
	}
	if a.Account != "user@domain.com" {
		t.Errorf("Account: got %q, want %q", a.Account, "user@domain.com")
	}
	if a.IP != "2.2.2.2" {
		t.Errorf("IP: got %q, want %q (IP del segundo login)", a.IP, "2.2.2.2")
	}
	if len(a.Reasons) == 0 || a.Reasons[0] == "" {
		t.Error("Reasons debe contener una descripción no vacía")
	}
}

func TestWindowExpiredNoAlert(t *testing.T) {
	m := impossibletraveler.New(defaultCfg, twoCountryGeoIP())
	now := time.Now()

	m.Handle(authEvent("user@domain.com", "1.1.1.1", now))
	// Más tiempo del permitido por la ventana → viaje posible
	later := now.Add(time.Duration(defaultCfg.WindowMinutes+1) * time.Minute)
	alerts := m.Handle(authEvent("user@domain.com", "2.2.2.2", later))
	if len(alerts) != 0 {
		t.Fatal("con ventana expirada no debe generarse alerta de viaje imposible")
	}
}

func TestExactWindowBoundaryNoAlert(t *testing.T) {
	m := impossibletraveler.New(defaultCfg, twoCountryGeoIP())
	now := time.Now()

	m.Handle(authEvent("user@domain.com", "1.1.1.1", now))
	// Exactamente en el límite de la ventana (>= window → no alerta)
	exactly := now.Add(time.Duration(defaultCfg.WindowMinutes) * time.Minute)
	alerts := m.Handle(authEvent("user@domain.com", "2.2.2.2", exactly))
	if len(alerts) != 0 {
		t.Fatal("en el límite exacto de la ventana no debe generarse alerta")
	}
}

func TestGeoIPFailureNoAlert(t *testing.T) {
	// GeoIP no puede resolver ninguna IP → no debe haber alertas
	geo := &mockGeoIP{countries: map[string]string{}}
	m := impossibletraveler.New(defaultCfg, geo)
	now := time.Now()

	m.Handle(authEvent("user@domain.com", "1.1.1.1", now))
	alerts := m.Handle(authEvent("user@domain.com", "2.2.2.2", now.Add(5*time.Minute)))
	if len(alerts) != 0 {
		t.Fatal("fallo GeoIP no debe generar alertas (evitar falsos positivos)")
	}
}

func TestGeoIPPartialFailureNoAlert(t *testing.T) {
	// Solo el primer IP resuelve; el segundo no → sin alerta
	geo := &mockGeoIP{countries: map[string]string{"1.1.1.1": "PE"}}
	m := impossibletraveler.New(defaultCfg, geo)
	now := time.Now()

	m.Handle(authEvent("user@domain.com", "1.1.1.1", now))
	alerts := m.Handle(authEvent("user@domain.com", "2.2.2.2", now.Add(5*time.Minute)))
	if len(alerts) != 0 {
		t.Fatal("si el segundo IP no resuelve no debe haber alerta")
	}
}

func TestRecordUpdatedAfterAlert(t *testing.T) {
	m := impossibletraveler.New(defaultCfg, twoCountryGeoIP())
	now := time.Now()

	// Primer login PE
	m.Handle(authEvent("user@domain.com", "1.1.1.1", now))
	// Segundo login CN → alerta, pero el record se actualiza a CN
	m.Handle(authEvent("user@domain.com", "2.2.2.2", now.Add(10*time.Minute)))

	// Tercer login CN (mismo país que el segundo) → sin alerta
	alerts := m.Handle(authEvent("user@domain.com", "2.2.2.2", now.Add(15*time.Minute)))
	if len(alerts) != 0 {
		t.Fatal("tras alerta, nuevo login desde mismo país no debe generar alerta")
	}
}

func TestIgnoresEmptyAccount(t *testing.T) {
	m := impossibletraveler.New(defaultCfg, twoCountryGeoIP())
	now := time.Now()

	ev := event.Event{
		Type:      event.AuthSuccess,
		Account:   "",
		IP:        "1.1.1.1",
		Timestamp: now,
	}
	if len(m.Handle(ev)) != 0 {
		t.Fatal("eventos sin cuenta no deben generar alertas")
	}
}

func TestIgnoresEmptyIP(t *testing.T) {
	m := impossibletraveler.New(defaultCfg, twoCountryGeoIP())
	now := time.Now()

	ev := event.Event{
		Type:      event.AuthSuccess,
		Account:   "user@domain.com",
		IP:        "",
		Timestamp: now,
	}
	if len(m.Handle(ev)) != 0 {
		t.Fatal("eventos sin IP no deben generar alertas")
	}
}

func TestIgnoresNonAuthSuccess(t *testing.T) {
	m := impossibletraveler.New(defaultCfg, twoCountryGeoIP())
	now := time.Now()

	otherTypes := []event.Type{
		event.AuthFailed, event.QueueAccepted,
		event.MessageSent, event.MessageBounce, event.MessageDeferred,
	}
	for _, t2 := range otherTypes {
		ev := event.Event{Type: t2, Account: "user@domain.com", IP: "1.1.1.1", Timestamp: now}
		if len(m.Handle(ev)) != 0 {
			t.Errorf("tipo %q no debe generar alertas en ImpossibleTraveler", t2)
		}
	}
}

func TestMultipleAccountsIndependent(t *testing.T) {
	m := impossibletraveler.New(defaultCfg, twoCountryGeoIP())
	now := time.Now()

	// Cuenta A: primer login PE
	m.Handle(authEvent("accountA@domain.com", "1.1.1.1", now))
	// Cuenta B: primer login CN (no debe afectar a cuenta A)
	m.Handle(authEvent("accountB@domain.com", "2.2.2.2", now))

	// Cuenta A: segundo login CN dentro de la ventana → alerta
	alertsA := m.Handle(authEvent("accountA@domain.com", "2.2.2.2", now.Add(10*time.Minute)))
	if len(alertsA) != 1 {
		t.Fatal("cuenta A debe generar alerta de viaje imposible")
	}

	// Cuenta B: segundo login PE dentro de la ventana → alerta independiente
	alertsB := m.Handle(authEvent("accountB@domain.com", "1.1.1.1", now.Add(10*time.Minute)))
	if len(alertsB) != 1 {
		t.Fatal("cuenta B debe generar alerta de viaje imposible independiente")
	}
}

func TestAllowedCountriesBothPermittedNoAlert(t *testing.T) {
	cfg := impossibletraveler.Config{
		WindowMinutes:    60,
		AllowedCountries: []string{"PE", "ES"},
	}
	geo := &mockGeoIP{countries: map[string]string{
		"1.1.1.1": "PE",
		"2.2.2.2": "ES",
	}}
	m := impossibletraveler.New(cfg, geo)
	now := time.Now()

	m.Handle(authEvent("user@domain.com", "1.1.1.1", now))
	alerts := m.Handle(authEvent("user@domain.com", "2.2.2.2", now.Add(5*time.Minute)))
	if len(alerts) != 0 {
		t.Fatal("ambos países en whitelist no debe generar alerta")
	}
}

func TestAllowedCountriesOneNotPermittedAlerts(t *testing.T) {
	cfg := impossibletraveler.Config{
		WindowMinutes:    60,
		AllowedCountries: []string{"PE"},
	}
	geo := &mockGeoIP{countries: map[string]string{
		"1.1.1.1": "PE",
		"2.2.2.2": "CN",
	}}
	m := impossibletraveler.New(cfg, geo)
	now := time.Now()

	m.Handle(authEvent("user@domain.com", "1.1.1.1", now))
	alerts := m.Handle(authEvent("user@domain.com", "2.2.2.2", now.Add(5*time.Minute)))
	if len(alerts) != 1 {
		t.Fatal("un país fuera de whitelist debe generar alerta")
	}
}

func TestTrustedProxyIgnored(t *testing.T) {
	cfg := impossibletraveler.Config{
		WindowMinutes: 60,
		TrustedCIDRs:  []string{"52.96.0.0/14"}, // rango de Microsoft
	}
	geo := &mockGeoIP{countries: map[string]string{
		"1.1.1.1":    "PE",
		"52.97.30.1": "US", // IP dentro del rango Microsoft
	}}
	m := impossibletraveler.New(cfg, geo)
	now := time.Now()

	// Login real desde PE
	m.Handle(authEvent("user@domain.com", "1.1.1.1", now))
	// Login desde proxy Microsoft — debe ignorarse por completo (sin alerta, sin actualizar ubicación)
	alerts := m.Handle(authEvent("user@domain.com", "52.97.30.1", now.Add(2*time.Minute)))
	if len(alerts) != 0 {
		t.Fatal("login desde proxy conocido no debe generar alerta")
	}

	// Login real desde PE de nuevo — no debe alertar (ubicación sigue siendo PE)
	alerts = m.Handle(authEvent("user@domain.com", "1.1.1.1", now.Add(5*time.Minute)))
	if len(alerts) != 0 {
		t.Fatal("login desde PE tras proxy Microsoft no debe alertar (ubicación no fue sobreescrita)")
	}
}

func TestTrustedProxyDoesNotOverwriteLocation(t *testing.T) {
	cfg := impossibletraveler.Config{
		WindowMinutes: 60,
		TrustedCIDRs:  []string{"52.96.0.0/14"},
	}
	geo := &mockGeoIP{countries: map[string]string{
		"1.1.1.1":    "PE",
		"52.97.30.1": "US",
		"3.3.3.3":    "CN",
	}}
	m := impossibletraveler.New(cfg, geo)
	now := time.Now()

	// Login PE → proxy Microsoft (ignorado) → login CN: debe alertar PE→CN, no US→CN
	m.Handle(authEvent("user@domain.com", "1.1.1.1", now))
	m.Handle(authEvent("user@domain.com", "52.97.30.1", now.Add(1*time.Minute)))
	alerts := m.Handle(authEvent("user@domain.com", "3.3.3.3", now.Add(2*time.Minute)))

	if len(alerts) != 1 {
		t.Fatalf("PE→(proxy ignorado)→CN debe generar 1 alerta, got %d", len(alerts))
	}
	// La razón debe mencionar PE como origen, no US
	if !strings.Contains(alerts[0].Reasons[0], "PE") {
		t.Errorf("la razón debe mencionar PE como origen: %s", alerts[0].Reasons[0])
	}
}

func TestTrustedProxyInvalidCIDRIgnored(t *testing.T) {
	// CIDRs inválidos no deben causar panic — simplemente se descartan.
	cfg := impossibletraveler.Config{
		WindowMinutes: 60,
		TrustedCIDRs:  []string{"no-es-un-cidr", "52.96.0.0/14"},
	}
	m := impossibletraveler.New(cfg, twoCountryGeoIP())
	if m == nil {
		t.Fatal("New no debe retornar nil con CIDRs inválidos mezclados")
	}
}

func TestTrustedOrgIgnored(t *testing.T) {
	cfg := impossibletraveler.Config{
		WindowMinutes: 60,
		TrustedOrgs:   []string{"Microsoft"},
	}
	geo := &mockGeoIP{
		countries: map[string]string{"1.1.1.1": "PE", "52.97.30.229": "US"},
		orgs:      map[string]string{"52.97.30.229": "AS8075 MICROSOFT-CORP-MSN-AS-BLOCK"},
	}
	m := impossibletraveler.New(cfg, geo)
	now := time.Now()

	m.Handle(authEvent("user@domain.com", "1.1.1.1", now))
	alerts := m.Handle(authEvent("user@domain.com", "52.97.30.229", now.Add(2*time.Minute)))
	if len(alerts) != 0 {
		t.Fatal("IP de Microsoft no debe generar alerta de impossible_traveler")
	}
}

func TestTrustedOrgDoesNotOverwriteLocation(t *testing.T) {
	cfg := impossibletraveler.Config{
		WindowMinutes: 60,
		TrustedOrgs:   []string{"Microsoft"},
	}
	geo := &mockGeoIP{
		countries: map[string]string{
			"1.1.1.1":     "PE",
			"52.97.30.229": "US",
			"3.3.3.3":     "CN",
		},
		orgs: map[string]string{
			"52.97.30.229": "AS8075 MICROSOFT-CORP-MSN-AS-BLOCK",
		},
	}
	m := impossibletraveler.New(cfg, geo)
	now := time.Now()

	// PE → Microsoft (ignorado) → CN: alerta debe decir PE→CN, no US→CN
	m.Handle(authEvent("user@domain.com", "1.1.1.1", now))
	m.Handle(authEvent("user@domain.com", "52.97.30.229", now.Add(1*time.Minute)))
	alerts := m.Handle(authEvent("user@domain.com", "3.3.3.3", now.Add(2*time.Minute)))

	if len(alerts) != 1 {
		t.Fatalf("PE→(Microsoft ignorado)→CN debe generar 1 alerta, got %d", len(alerts))
	}
	if !strings.Contains(alerts[0].Reasons[0], "PE") {
		t.Errorf("la razón debe mencionar PE como origen: %s", alerts[0].Reasons[0])
	}
}

func TestTrustedOrgCaseInsensitive(t *testing.T) {
	cfg := impossibletraveler.Config{
		WindowMinutes: 60,
		TrustedOrgs:   []string{"microsoft"}, // minúsculas
	}
	geo := &mockGeoIP{
		countries: map[string]string{"1.1.1.1": "PE", "2.2.2.2": "US"},
		orgs:      map[string]string{"2.2.2.2": "AS8075 MICROSOFT-CORP-MSN-AS-BLOCK"}, // mayúsculas
	}
	m := impossibletraveler.New(cfg, geo)
	now := time.Now()

	m.Handle(authEvent("user@domain.com", "1.1.1.1", now))
	alerts := m.Handle(authEvent("user@domain.com", "2.2.2.2", now.Add(5*time.Minute)))
	if len(alerts) != 0 {
		t.Fatal("la comparación de org debe ser case-insensitive")
	}
}

func TestAllowedCountriesEmptyListAlwaysAlerts(t *testing.T) {
	// Sin allowed_countries configurado, cualquier cambio de país alerta.
	m := impossibletraveler.New(defaultCfg, twoCountryGeoIP())
	now := time.Now()

	m.Handle(authEvent("user@domain.com", "1.1.1.1", now))
	alerts := m.Handle(authEvent("user@domain.com", "2.2.2.2", now.Add(5*time.Minute)))
	if len(alerts) != 1 {
		t.Fatal("sin whitelist de países cualquier cambio de país debe alertar")
	}
}

func TestDomainPropagated(t *testing.T) {
	m := impossibletraveler.New(defaultCfg, twoCountryGeoIP())
	now := time.Now()

	m.Handle(authEvent("user@example.com", "1.1.1.1", now))
	alerts := m.Handle(authEvent("user@example.com", "2.2.2.2", now.Add(5*time.Minute)))

	if len(alerts) != 1 {
		t.Fatal("se esperaba una alerta")
	}
	if alerts[0].Domain != "example.com" {
		t.Errorf("Domain: got %q, want %q", alerts[0].Domain, "example.com")
	}
}
