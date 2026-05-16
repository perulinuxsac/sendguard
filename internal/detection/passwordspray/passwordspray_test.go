package passwordspray

import (
	"testing"
	"time"

	"github.com/perulinux/sendguard/internal/detection"
	"github.com/perulinux/sendguard/internal/event"
)

func cfg() Config {
	return Config{MaxAccounts: 3, ScanTime: time.Minute}
}

func ev(ip, account string, t time.Time) event.Event {
	return event.Event{
		Type:      event.AuthFailed,
		IP:        ip,
		Account:   account,
		Timestamp: t,
		Server:    "mail1",
	}
}

func TestName(t *testing.T) {
	if New(cfg()).Name() != "password_spray" {
		t.Error("Name() debe retornar password_spray")
	}
}

func TestIgnoraEventosNoAuthFailed(t *testing.T) {
	m := New(cfg())
	e := ev("1.2.3.4", "user@x.com", time.Now())
	e.Type = event.MessageSent
	if got := m.Handle(e); len(got) != 0 {
		t.Errorf("evento no AuthFailed debe ignorarse, got %d alertas", len(got))
	}
}

func TestIgnoraSinIP(t *testing.T) {
	m := New(cfg())
	e := ev("", "user@x.com", time.Now())
	if got := m.Handle(e); len(got) != 0 {
		t.Errorf("evento sin IP debe ignorarse, got %d alertas", len(got))
	}
}

func TestIgnoraSinCuenta(t *testing.T) {
	m := New(cfg())
	e := ev("1.2.3.4", "", time.Now())
	if got := m.Handle(e); len(got) != 0 {
		t.Errorf("evento sin cuenta debe ignorarse, got %d alertas", len(got))
	}
}

func TestSinAlertaBajoUmbral(t *testing.T) {
	m := New(cfg())
	now := time.Now()
	m.Handle(ev("1.2.3.4", "a@x.com", now))
	m.Handle(ev("1.2.3.4", "b@x.com", now.Add(time.Second)))
	alerts := m.Handle(ev("1.2.3.4", "b@x.com", now.Add(2*time.Second))) // cuenta repetida
	if len(alerts) != 0 {
		t.Errorf("mismo umbral no alcanzado: got %d alertas", len(alerts))
	}
}

func TestAlertaAlAlcanzarUmbral(t *testing.T) {
	m := New(cfg()) // MaxAccounts=3
	now := time.Now()
	m.Handle(ev("1.2.3.4", "a@x.com", now))
	m.Handle(ev("1.2.3.4", "b@x.com", now.Add(time.Second)))
	alerts := m.Handle(ev("1.2.3.4", "c@x.com", now.Add(2*time.Second)))

	if len(alerts) != 1 {
		t.Fatalf("umbral alcanzado: esperada 1 alerta, got %d", len(alerts))
	}
	a := alerts[0]
	if a.Action != detection.ActionBlockIP {
		t.Errorf("Action: got %q, want block_ip", a.Action)
	}
	if a.IP != "1.2.3.4" {
		t.Errorf("IP: got %q, want 1.2.3.4", a.IP)
	}
	if a.Score < 80 {
		t.Errorf("Score: got %d, want >= 80", a.Score)
	}
}

func TestResetTrasAlerta(t *testing.T) {
	m := New(cfg())
	now := time.Now()
	m.Handle(ev("1.2.3.4", "a@x.com", now))
	m.Handle(ev("1.2.3.4", "b@x.com", now.Add(time.Second)))
	m.Handle(ev("1.2.3.4", "c@x.com", now.Add(2*time.Second))) // dispara alerta y limpia

	// Volver a contar desde cero
	m.Handle(ev("1.2.3.4", "d@x.com", now.Add(3*time.Second)))
	m.Handle(ev("1.2.3.4", "e@x.com", now.Add(4*time.Second)))
	alerts := m.Handle(ev("1.2.3.4", "f@x.com", now.Add(5*time.Second)))
	if len(alerts) != 1 {
		t.Errorf("segunda ronda: esperada 1 alerta, got %d", len(alerts))
	}
}

func TestVentanaDeslizante(t *testing.T) {
	m := New(Config{MaxAccounts: 3, ScanTime: 10 * time.Second})
	base := time.Now()

	m.Handle(ev("5.5.5.5", "a@x.com", base))
	m.Handle(ev("5.5.5.5", "b@x.com", base.Add(2*time.Second)))

	// El tercero llega fuera de la ventana del primero → solo 2 cuentas activas
	alerts := m.Handle(ev("5.5.5.5", "c@x.com", base.Add(11*time.Second)))
	if len(alerts) != 0 {
		t.Errorf("con ventana expirada no debe alertar, got %d alertas", len(alerts))
	}
}

func TestIPsIndependientes(t *testing.T) {
	m := New(cfg())
	now := time.Now()

	m.Handle(ev("1.1.1.1", "a@x.com", now))
	m.Handle(ev("1.1.1.1", "b@x.com", now.Add(time.Second)))

	// Segunda IP: no debe compartir ventana con la primera
	m.Handle(ev("2.2.2.2", "c@x.com", now))
	m.Handle(ev("2.2.2.2", "d@x.com", now.Add(time.Second)))
	alerts := m.Handle(ev("2.2.2.2", "e@x.com", now.Add(2*time.Second)))

	if len(alerts) != 1 || alerts[0].IP != "2.2.2.2" {
		t.Errorf("segunda IP independiente debe alertar por su cuenta: %v", alerts)
	}
}

func TestRazonContieneInfo(t *testing.T) {
	m := New(cfg())
	now := time.Now()
	m.Handle(ev("9.9.9.9", "a@x.com", now))
	m.Handle(ev("9.9.9.9", "b@x.com", now.Add(time.Second)))
	alerts := m.Handle(ev("9.9.9.9", "c@x.com", now.Add(2*time.Second)))

	if len(alerts) == 0 {
		t.Fatal("se esperaba una alerta")
	}
	reason := alerts[0].Reasons[0]
	if !contains(reason, "9.9.9.9") {
		t.Errorf("razón debe contener la IP: %q", reason)
	}
	if !contains(reason, "password spraying") {
		t.Errorf("razón debe mencionar password spraying: %q", reason)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsRune(s, sub))
}

func containsRune(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
