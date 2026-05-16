package accounttakeover

import (
	"testing"
	"time"

	"github.com/perulinux/sendguard/internal/detection"
	"github.com/perulinux/sendguard/internal/event"
)

func cfg() Config { return Config{MinFailures: 3, CorrelWindow: time.Minute} }

func evFail(ip, account string, t time.Time) event.Event {
	return event.Event{Type: event.AuthFailed, IP: ip, Account: account, Timestamp: t, Server: "mail1"}
}
func evSuccess(ip, account string, t time.Time) event.Event {
	return event.Event{Type: event.AuthSuccess, IP: ip, Account: account, Timestamp: t, Server: "mail1"}
}
func evQueue(account string, t time.Time) event.Event {
	return event.Event{Type: event.QueueAccepted, Account: account, Timestamp: t, Server: "mail1"}
}

func TestName(t *testing.T) {
	if New(cfg()).Name() != "account_takeover" {
		t.Error("Name() debe retornar account_takeover")
	}
}

func TestSinAlertaSinFallos(t *testing.T) {
	m := New(cfg())
	now := time.Now()
	alerts := m.Handle(evSuccess("1.2.3.4", "user@x.com", now))
	if len(alerts) != 0 {
		t.Errorf("auth_success sin fallos previos no debe alertar, got %d", len(alerts))
	}
}

func TestPatron1_MismaIP(t *testing.T) {
	m := New(cfg())
	now := time.Now()
	ip := "1.2.3.4"
	account := "victim@x.com"

	m.Handle(evFail(ip, account, now))
	m.Handle(evFail(ip, account, now.Add(time.Second)))
	m.Handle(evFail(ip, account, now.Add(2*time.Second)))
	alerts := m.Handle(evSuccess(ip, account, now.Add(3*time.Second)))

	if len(alerts) != 1 {
		t.Fatalf("patrón 1: esperada 1 alerta, got %d", len(alerts))
	}
	a := alerts[0]
	if a.Action != detection.ActionSuspendAcct {
		t.Errorf("Action: got %q, want suspend_account", a.Action)
	}
	if a.Score < 90 {
		t.Errorf("Score patrón 1: got %d, want >= 90", a.Score)
	}
	if a.IP != ip {
		t.Errorf("IP: got %q, want %q", a.IP, ip)
	}
	if a.Account != account {
		t.Errorf("Account: got %q, want %q", a.Account, account)
	}
}

func TestPatron1_IPDistintaNoAlertas(t *testing.T) {
	m := New(cfg())
	now := time.Now()
	account := "victim@x.com"

	// Fallos desde 1.2.3.4
	m.Handle(evFail("1.2.3.4", account, now))
	m.Handle(evFail("1.2.3.4", account, now.Add(time.Second)))
	m.Handle(evFail("1.2.3.4", account, now.Add(2*time.Second)))

	// Auth exitoso desde IP distinta — no es el atacante
	alerts := m.Handle(evSuccess("9.9.9.9", account, now.Add(3*time.Second)))
	if len(alerts) != 0 {
		t.Errorf("patrón 1 con IP distinta no debe alertar, got %d", len(alerts))
	}
}

func TestPatron2_QueueAccepted(t *testing.T) {
	m := New(cfg())
	now := time.Now()
	ip := "5.5.5.5"
	account := "victim@x.com"

	m.Handle(evFail(ip, account, now))
	m.Handle(evFail(ip, account, now.Add(time.Second)))
	m.Handle(evFail(ip, account, now.Add(2*time.Second)))
	alerts := m.Handle(evQueue(account, now.Add(3*time.Second)))

	if len(alerts) != 1 {
		t.Fatalf("patrón 2: esperada 1 alerta, got %d", len(alerts))
	}
	a := alerts[0]
	if a.Score < 80 {
		t.Errorf("Score patrón 2: got %d, want >= 80", a.Score)
	}
	if a.IP != ip {
		t.Errorf("IP atacante: got %q, want %q", a.IP, ip)
	}
}

func TestPatron2_BajoUmbral(t *testing.T) {
	m := New(cfg()) // MinFailures=3
	now := time.Now()
	account := "user@x.com"

	m.Handle(evFail("1.1.1.1", account, now))
	m.Handle(evFail("1.1.1.1", account, now.Add(time.Second)))
	// Solo 2 fallos, < MinFailures
	alerts := m.Handle(evQueue(account, now.Add(2*time.Second)))
	if len(alerts) != 0 {
		t.Errorf("bajo umbral no debe alertar, got %d", len(alerts))
	}
}

func TestVentanaExpira(t *testing.T) {
	m := New(Config{MinFailures: 3, CorrelWindow: 5 * time.Second})
	base := time.Now()
	account := "victim@x.com"
	ip := "2.2.2.2"

	m.Handle(evFail(ip, account, base))
	m.Handle(evFail(ip, account, base.Add(time.Second)))
	m.Handle(evFail(ip, account, base.Add(2*time.Second)))

	// Auth exitoso fuera de la ventana — fallos ya expirados
	alerts := m.Handle(evSuccess(ip, account, base.Add(10*time.Second)))
	if len(alerts) != 0 {
		t.Errorf("fuera de ventana no debe alertar, got %d", len(alerts))
	}
}

func TestResetTrasSuspension(t *testing.T) {
	m := New(cfg())
	now := time.Now()
	ip := "3.3.3.3"
	account := "victim@x.com"

	// Primera ronda — dispara patrón 1
	m.Handle(evFail(ip, account, now))
	m.Handle(evFail(ip, account, now.Add(time.Second)))
	m.Handle(evFail(ip, account, now.Add(2*time.Second)))
	first := m.Handle(evSuccess(ip, account, now.Add(3*time.Second)))
	if len(first) != 1 {
		t.Fatalf("primera ronda: esperada 1 alerta, got %d", len(first))
	}

	// Segunda ronda — estado limpiado, no debe alertar con mismos fallos
	m.Handle(evFail(ip, account, now.Add(4*time.Second)))
	m.Handle(evFail(ip, account, now.Add(5*time.Second)))
	second := m.Handle(evSuccess(ip, account, now.Add(6*time.Second)))
	if len(second) != 0 {
		t.Errorf("segunda ronda sin umbral: got %d alertas", len(second))
	}
}

func TestIPDominante(t *testing.T) {
	m := New(cfg())
	now := time.Now()
	account := "victim@x.com"

	// IP "A" 2 fallos, IP "B" 3 fallos — dominante es B
	m.Handle(evFail("10.0.0.1", account, now))
	m.Handle(evFail("10.0.0.1", account, now.Add(time.Second)))
	m.Handle(evFail("10.0.0.2", account, now.Add(2*time.Second)))
	m.Handle(evFail("10.0.0.2", account, now.Add(3*time.Second)))
	m.Handle(evFail("10.0.0.2", account, now.Add(4*time.Second)))

	alerts := m.Handle(evQueue(account, now.Add(5*time.Second)))
	if len(alerts) != 1 {
		t.Fatalf("esperada 1 alerta, got %d", len(alerts))
	}
	if alerts[0].IP != "10.0.0.2" {
		t.Errorf("IP dominante: got %q, want 10.0.0.2", alerts[0].IP)
	}
}

func TestCuentasIndependientes(t *testing.T) {
	m := New(cfg())
	now := time.Now()

	// Cuenta A: 3 fallos pero sin auth_success/queue — no alerta
	m.Handle(evFail("1.1.1.1", "a@x.com", now))
	m.Handle(evFail("1.1.1.1", "a@x.com", now.Add(time.Second)))
	m.Handle(evFail("1.1.1.1", "a@x.com", now.Add(2*time.Second)))

	// Cuenta B: 3 fallos + queue → alerta solo para B
	m.Handle(evFail("2.2.2.2", "b@x.com", now))
	m.Handle(evFail("2.2.2.2", "b@x.com", now.Add(time.Second)))
	m.Handle(evFail("2.2.2.2", "b@x.com", now.Add(2*time.Second)))
	alerts := m.Handle(evQueue("b@x.com", now.Add(3*time.Second)))

	if len(alerts) != 1 || alerts[0].Account != "b@x.com" {
		t.Errorf("solo cuenta b debe alertar: %v", alerts)
	}
}

func TestRazonContieneDatos(t *testing.T) {
	m := New(cfg())
	now := time.Now()
	ip, account := "7.7.7.7", "target@x.com"

	m.Handle(evFail(ip, account, now))
	m.Handle(evFail(ip, account, now.Add(time.Second)))
	m.Handle(evFail(ip, account, now.Add(2*time.Second)))
	alerts := m.Handle(evSuccess(ip, account, now.Add(3*time.Second)))

	if len(alerts) == 0 {
		t.Fatal("se esperaba alerta")
	}
	reason := alerts[0].Reasons[0]
	for _, want := range []string{ip, account, "fuerza bruta"} {
		if !contains(reason, want) {
			t.Errorf("razón debe contener %q: %q", want, reason)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
