package detection

import (
	"testing"
	"time"

	"github.com/perulinux/sendguard/internal/event"
)

// --- NewWhitelist / ContainsIP ---

func TestWhitelistIPIndividual(t *testing.T) {
	wl := NewWhitelist([]string{"192.168.1.10"}, nil)
	if !wl.ContainsIP("192.168.1.10") {
		t.Error("IP exacta debe estar en whitelist")
	}
	if wl.ContainsIP("192.168.1.11") {
		t.Error("IP diferente no debe estar en whitelist")
	}
}

func TestWhitelistCIDR(t *testing.T) {
	wl := NewWhitelist([]string{"10.0.0.0/8"}, nil)
	for _, ip := range []string{"10.0.0.1", "10.255.255.255", "10.1.2.3"} {
		if !wl.ContainsIP(ip) {
			t.Errorf("ContainsIP(%q): debe estar en 10.0.0.0/8", ip)
		}
	}
	if wl.ContainsIP("11.0.0.1") {
		t.Error("11.0.0.1 no debe estar en 10.0.0.0/8")
	}
}

func TestWhitelistIPInvalida(t *testing.T) {
	wl := NewWhitelist([]string{"not-an-ip"}, nil)
	// La entrada inválida se ignora; la whitelist queda vacía.
	if wl.ContainsIP("1.2.3.4") {
		t.Error("whitelist con entrada inválida no debe contener IPs")
	}
}

func TestWhitelistVacia(t *testing.T) {
	wl := NewWhitelist(nil, nil)
	if wl.ContainsIP("1.2.3.4") {
		t.Error("whitelist vacía no debe contener ninguna IP")
	}
}

// --- NewWhitelist / ContainsAccount ---

func TestWhitelistAccount(t *testing.T) {
	wl := NewWhitelist(nil, []string{"admin@example.com", "noc@example.com"})
	if !wl.ContainsAccount("admin@example.com") {
		t.Error("admin@example.com debe estar en whitelist")
	}
	if wl.ContainsAccount("user@example.com") {
		t.Error("user@example.com no debe estar en whitelist")
	}
}

func TestWhitelistAccountVacia(t *testing.T) {
	wl := NewWhitelist(nil, nil)
	if wl.ContainsAccount("anyone@example.com") {
		t.Error("whitelist vacía no debe contener cuentas")
	}
}

// --- mockModule para probar el Engine ---

type mockModule struct {
	name    string
	alerts  []Alert
	handled []event.Event
}

func (m *mockModule) Name() string { return m.name }
func (m *mockModule) Handle(ev event.Event) []Alert {
	m.handled = append(m.handled, ev)
	return m.alerts
}

// --- Engine.dispatch / isWhitelisted ---

func TestEngineDispatchEnviaAlerta(t *testing.T) {
	alertCh := make(chan Alert, 10)
	mod := &mockModule{
		name:   "test",
		alerts: []Alert{{Module: "test", Score: 100}},
	}
	wl := NewWhitelist(nil, nil)
	eng := NewEngine(alertCh, wl, mod)

	ev := event.Event{Type: event.AuthFailed, IP: "1.2.3.4", Timestamp: time.Now()}
	eng.dispatch(ev)

	if len(alertCh) != 1 {
		t.Fatalf("alertCh: got %d alertas, want 1", len(alertCh))
	}
	a := <-alertCh
	if a.Module != "test" {
		t.Errorf("Module: got %q, want test", a.Module)
	}
}

func TestEngineDispatchIPEnWhitelistNoLlamaMódulo(t *testing.T) {
	alertCh := make(chan Alert, 10)
	mod := &mockModule{name: "test", alerts: []Alert{{Module: "test"}}}
	wl := NewWhitelist([]string{"1.2.3.4"}, nil)
	eng := NewEngine(alertCh, wl, mod)

	eng.dispatch(event.Event{IP: "1.2.3.4", Timestamp: time.Now()})

	if len(mod.handled) != 0 {
		t.Error("módulo no debe recibir eventos de IPs en whitelist")
	}
	if len(alertCh) != 0 {
		t.Error("no deben generarse alertas para IPs en whitelist")
	}
}

func TestEngineDispatchCuentaEnWhitelistNoLlamaMódulo(t *testing.T) {
	alertCh := make(chan Alert, 10)
	mod := &mockModule{name: "test", alerts: []Alert{{Module: "test"}}}
	wl := NewWhitelist(nil, []string{"safe@example.com"})
	eng := NewEngine(alertCh, wl, mod)

	eng.dispatch(event.Event{Account: "safe@example.com", Timestamp: time.Now()})

	if len(mod.handled) != 0 {
		t.Error("módulo no debe recibir eventos de cuentas en whitelist")
	}
}

func TestEngineDispatchCanalLlenoDescarta(t *testing.T) {
	// Canal con capacidad 0 — el envío debe descartarse sin bloquear.
	alertCh := make(chan Alert, 0)
	mod := &mockModule{name: "test", alerts: []Alert{{Module: "test"}}}
	wl := NewWhitelist(nil, nil)
	eng := NewEngine(alertCh, wl, mod)

	// No debe bloquearse aunque el canal esté lleno.
	done := make(chan struct{})
	go func() {
		eng.dispatch(event.Event{IP: "9.9.9.9", Timestamp: time.Now()})
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("dispatch bloqueó con canal lleno")
	}
}

func TestEngineDispatchMultiplesModulos(t *testing.T) {
	alertCh := make(chan Alert, 10)
	mod1 := &mockModule{name: "mod1", alerts: []Alert{{Module: "mod1"}}}
	mod2 := &mockModule{name: "mod2", alerts: []Alert{{Module: "mod2"}, {Module: "mod2"}}}
	wl := NewWhitelist(nil, nil)
	eng := NewEngine(alertCh, wl, mod1, mod2)

	eng.dispatch(event.Event{IP: "5.5.5.5", Timestamp: time.Now()})

	// mod1 emite 1 alerta, mod2 emite 2 → total 3.
	if len(alertCh) != 3 {
		t.Errorf("alertCh: got %d, want 3", len(alertCh))
	}
}

func TestEngineContadoresEventosYAlertas(t *testing.T) {
	alertCh := make(chan Alert, 10)
	mod := &mockModule{name: "test", alerts: []Alert{{Module: "test"}, {Module: "test"}}}
	wl := NewWhitelist(nil, nil)
	eng := NewEngine(alertCh, wl, mod)

	eng.dispatch(event.Event{IP: "1.1.1.1", Timestamp: time.Now()})
	eng.dispatch(event.Event{IP: "2.2.2.2", Timestamp: time.Now()})

	if n := eng.EventsTotal.Load(); n != 2 {
		t.Errorf("EventsTotal: got %d, want 2", n)
	}
	// 2 eventos × 2 alertas por módulo = 4 alertas.
	if n := eng.AlertsTotal.Load(); n != 4 {
		t.Errorf("AlertsTotal: got %d, want 4", n)
	}
}

func TestEngineContadorEventoIPWhitelistedSeCuenta(t *testing.T) {
	// Los eventos whitelisteados sí incrementan EventsTotal pero no AlertsTotal.
	alertCh := make(chan Alert, 10)
	mod := &mockModule{name: "test", alerts: []Alert{{Module: "test"}}}
	wl := NewWhitelist([]string{"1.2.3.4"}, nil)
	eng := NewEngine(alertCh, wl, mod)

	eng.dispatch(event.Event{IP: "1.2.3.4", Timestamp: time.Now()})

	if n := eng.EventsTotal.Load(); n != 1 {
		t.Errorf("EventsTotal: got %d, want 1 (whitelistados aún se cuentan)", n)
	}
	if n := eng.AlertsTotal.Load(); n != 0 {
		t.Errorf("AlertsTotal: got %d, want 0 (whitelistados no generan alertas)", n)
	}
}

func TestEngineSinModulosNoBloquea(t *testing.T) {
	alertCh := make(chan Alert, 10)
	wl := NewWhitelist(nil, nil)
	eng := NewEngine(alertCh, wl) // sin módulos

	eng.dispatch(event.Event{IP: "1.2.3.4", Timestamp: time.Now()})

	if len(alertCh) != 0 {
		t.Error("sin módulos no debe haber alertas")
	}
	if n := eng.EventsTotal.Load(); n != 1 {
		t.Errorf("EventsTotal: got %d, want 1", n)
	}
}

// --- Whitelist dinámica ---

func TestWhitelistAddIPDinamico(t *testing.T) {
	wl := NewWhitelist(nil, nil)
	if err := wl.AddIP("10.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if !wl.ContainsIP("10.0.0.1") {
		t.Error("AddIP: IP debe estar en whitelist")
	}
}

func TestWhitelistAddIPCIDR(t *testing.T) {
	wl := NewWhitelist(nil, nil)
	if err := wl.AddIP("192.168.0.0/24"); err != nil {
		t.Fatal(err)
	}
	if !wl.ContainsIP("192.168.0.50") {
		t.Error("AddIP CIDR: IP del rango debe estar en whitelist")
	}
}

func TestWhitelistAddIPInvalida(t *testing.T) {
	wl := NewWhitelist(nil, nil)
	if err := wl.AddIP("no-es-ip"); err == nil {
		t.Error("AddIP con IP inválida debe retornar error")
	}
}

func TestWhitelistRemoveIP(t *testing.T) {
	wl := NewWhitelist([]string{"5.5.5.5"}, nil)
	wl.RemoveIP("5.5.5.5")
	if wl.ContainsIP("5.5.5.5") {
		t.Error("RemoveIP: IP no debe estar en whitelist tras eliminarla")
	}
}

func TestWhitelistRemoveIPNoExistente(t *testing.T) {
	wl := NewWhitelist(nil, nil)
	wl.RemoveIP("9.9.9.9") // no debe panic
}

func TestWhitelistAddRemoveAccount(t *testing.T) {
	wl := NewWhitelist(nil, nil)
	wl.AddAccount("user@example.com")
	if !wl.ContainsAccount("user@example.com") {
		t.Error("AddAccount: cuenta debe estar en whitelist")
	}
	wl.RemoveAccount("user@example.com")
	if wl.ContainsAccount("user@example.com") {
		t.Error("RemoveAccount: cuenta no debe estar en whitelist")
	}
}

func TestWhitelistList(t *testing.T) {
	wl := NewWhitelist([]string{"1.2.3.4"}, []string{"admin@example.com"})
	ips, accounts := wl.List()
	if len(ips) != 1 {
		t.Errorf("List ips: got %d, want 1", len(ips))
	}
	if len(accounts) != 1 {
		t.Errorf("List accounts: got %d, want 1", len(accounts))
	}
}

// --- Engine.DomainStats ---

func TestEngineDomainStatsPorAccount(t *testing.T) {
	alertCh := make(chan Alert, 10)
	mod := &mockModule{
		name:   "test",
		alerts: []Alert{{Module: "test", Account: "user@example.com"}},
	}
	eng := NewEngine(alertCh, NewWhitelist(nil, nil), mod)

	eng.dispatch(event.Event{IP: "1.2.3.4", Timestamp: time.Now()})

	stats := eng.DomainStats()
	if len(stats) != 1 || stats[0].Domain != "example.com" || stats[0].Alerts != 1 {
		t.Errorf("DomainStats: got %v", stats)
	}
}

func TestEngineDomainStatsPorDomainField(t *testing.T) {
	alertCh := make(chan Alert, 10)
	mod := &mockModule{
		name:   "test",
		alerts: []Alert{{Module: "test", Domain: "target.com"}},
	}
	eng := NewEngine(alertCh, NewWhitelist(nil, nil), mod)

	eng.dispatch(event.Event{IP: "2.2.2.2", Timestamp: time.Now()})

	stats := eng.DomainStats()
	if len(stats) != 1 || stats[0].Domain != "target.com" {
		t.Errorf("DomainStats domain field: got %v", stats)
	}
}

func TestEngineDomainStatsSinDominio(t *testing.T) {
	alertCh := make(chan Alert, 10)
	mod := &mockModule{
		name:   "test",
		alerts: []Alert{{Module: "test"}}, // sin Account ni Domain
	}
	eng := NewEngine(alertCh, NewWhitelist(nil, nil), mod)

	eng.dispatch(event.Event{IP: "3.3.3.3", Timestamp: time.Now()})

	if len(eng.DomainStats()) != 0 {
		t.Error("alerta sin dominio no debe registrar domain stats")
	}
}

// --- SeverityFromScore ---

func TestSeverityFromScore(t *testing.T) {
	casos := []struct {
		score    int
		expected Severity
	}{
		{0, SeverityLog},
		{29, SeverityLog},
		{30, SeverityWarn},
		{49, SeverityWarn},
		{50, SeverityRateLimit},
		{79, SeverityRateLimit},
		{80, SeveritySuspend},
		{100, SeveritySuspend},
	}
	for _, c := range casos {
		got := SeverityFromScore(c.score)
		if got != c.expected {
			t.Errorf("SeverityFromScore(%d): got %d, want %d", c.score, got, c.expected)
		}
	}
}
