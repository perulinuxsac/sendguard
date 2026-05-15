package distbrute_test

import (
	"testing"
	"time"

	"github.com/perulinux/sendguard/internal/detection"
	"github.com/perulinux/sendguard/internal/detection/distbrute"
	"github.com/perulinux/sendguard/internal/event"
)

var defaultCfg = distbrute.Config{
	MaxIPs:   3,
	ScanTime: 5 * time.Minute,
}

func failEv(ip, account string, ts time.Time) event.Event {
	return event.Event{
		Type:      event.AuthFailed,
		IP:        ip,
		Account:   account,
		Domain:    "example.com",
		Server:    "mail01",
		Timestamp: ts,
	}
}

func TestBelowThreshold(t *testing.T) {
	m := distbrute.New(defaultCfg)
	now := time.Now()

	for i := 0; i < defaultCfg.MaxIPs-1; i++ {
		ip := []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"}[i]
		alerts := m.Handle(failEv(ip, "victim@example.com", now.Add(time.Duration(i)*time.Second)))
		if len(alerts) != 0 {
			t.Fatalf("IP %d: no debe haber alerta antes del umbral", i+1)
		}
	}
}

func TestAtThreshold(t *testing.T) {
	m := distbrute.New(defaultCfg)
	now := time.Now()

	ips := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}
	var alerts []detection.Alert
	for i, ip := range ips {
		alerts = m.Handle(failEv(ip, "ceo@example.com", now.Add(time.Duration(i)*time.Second)))
	}

	if len(alerts) != 1 {
		t.Fatalf("got %d alertas, want 1", len(alerts))
	}
	a := alerts[0]
	if a.Action != detection.ActionNotifyOnly {
		t.Errorf("Action: got %q, want ActionNotifyOnly", a.Action)
	}
	if a.Module != "dist_brute_force" {
		t.Errorf("Module: got %q, want dist_brute_force", a.Module)
	}
	if a.Account != "ceo@example.com" {
		t.Errorf("Account: got %q, want ceo@example.com", a.Account)
	}
	if a.Score != 55 {
		t.Errorf("Score: got %d, want 55", a.Score)
	}
	if len(a.Reasons) == 0 {
		t.Error("Reasons no debe estar vacío")
	}
}

func TestDuplicateIPNotCounted(t *testing.T) {
	m := distbrute.New(defaultCfg)
	now := time.Now()

	// La misma IP N veces no debe contar como N IPs distintas.
	for i := 0; i < defaultCfg.MaxIPs*3; i++ {
		alerts := m.Handle(failEv("9.9.9.9", "user@example.com", now.Add(time.Duration(i)*time.Second)))
		if len(alerts) != 0 {
			t.Fatal("IP repetida no debe disparar la alerta de IPs distintas")
		}
	}
}

func TestWindowExpiry(t *testing.T) {
	m := distbrute.New(defaultCfg)
	now := time.Now()

	m.Handle(failEv("1.1.1.1", "user@example.com", now))
	m.Handle(failEv("2.2.2.2", "user@example.com", now))

	// Evento fuera de ventana: los anteriores deben expirar.
	future := now.Add(defaultCfg.ScanTime + time.Second)
	alerts := m.Handle(failEv("3.3.3.3", "user@example.com", future))
	if len(alerts) != 0 {
		t.Fatal("eventos viejos deben expirar: no debería generarse alerta")
	}
}

func TestResetAfterAlert(t *testing.T) {
	m := distbrute.New(defaultCfg)
	now := time.Now()

	ips := []string{"10.0.1.1", "10.0.1.2", "10.0.1.3"}
	for i, ip := range ips {
		m.Handle(failEv(ip, "user@example.com", now.Add(time.Duration(i)*time.Second)))
	}

	// Tras la alerta, la cuenta se resetea. Más fallos no deben disparar inmediatamente.
	later := now.Add(time.Minute)
	for i := 0; i < defaultCfg.MaxIPs-1; i++ {
		ip := []string{"20.0.1.1", "20.0.1.2"}[i]
		alerts := m.Handle(failEv(ip, "user@example.com", later.Add(time.Duration(i)*time.Second)))
		if len(alerts) != 0 {
			t.Error("tras reset, MaxIPs-1 no debe generar alerta")
		}
	}
}

func TestMultipleAccountsIndependent(t *testing.T) {
	m := distbrute.New(defaultCfg)
	now := time.Now()

	// cuenta A llega al umbral
	for i, ip := range []string{"1.0.0.1", "1.0.0.2", "1.0.0.3"} {
		m.Handle(failEv(ip, "accountA@example.com", now.Add(time.Duration(i)*time.Second)))
	}

	// cuenta B: MaxIPs-1 IPs distintas → sin alerta
	for i, ip := range []string{"2.0.0.1", "2.0.0.2"} {
		alerts := m.Handle(failEv(ip, "accountB@example.com", now.Add(time.Duration(i)*time.Second)))
		if len(alerts) != 0 {
			t.Errorf("accountB no debe alertar antes del umbral (intento %d)", i+1)
		}
	}
}

func TestIgnoresNonAuthFailed(t *testing.T) {
	m := distbrute.New(defaultCfg)
	now := time.Now()

	for _, evType := range []event.Type{event.AuthSuccess, event.QueueAccepted, event.MessageSent} {
		ev := event.Event{Type: evType, IP: "5.5.5.5", Account: "u@d.com", Timestamp: now}
		if alerts := m.Handle(ev); len(alerts) != 0 {
			t.Errorf("tipo %q no debe generar alertas", evType)
		}
	}
}

func TestIgnoresEmptyIP(t *testing.T) {
	m := distbrute.New(defaultCfg)
	now := time.Now()
	for i := 0; i < defaultCfg.MaxIPs*2; i++ {
		ev := event.Event{Type: event.AuthFailed, IP: "", Account: "u@d.com", Timestamp: now}
		if alerts := m.Handle(ev); len(alerts) != 0 {
			t.Fatal("IP vacía no debe generar alerta")
		}
	}
}

func TestIgnoresEmptyAccount(t *testing.T) {
	m := distbrute.New(defaultCfg)
	now := time.Now()
	ips := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"}
	for _, ip := range ips {
		ev := event.Event{Type: event.AuthFailed, IP: ip, Account: "", Timestamp: now}
		if alerts := m.Handle(ev); len(alerts) != 0 {
			t.Fatal("Account vacío no debe generar alerta")
		}
	}
}
