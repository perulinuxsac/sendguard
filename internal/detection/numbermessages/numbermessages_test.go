package numbermessages_test

import (
	"testing"
	"time"

	"github.com/perulinux/sendguard/internal/detection"
	"github.com/perulinux/sendguard/internal/detection/numbermessages"
	"github.com/perulinux/sendguard/internal/event"
)

var defaultCfg = numbermessages.Config{
	MaxMessages: 10,
	ScanTime:    1 * time.Hour,
}

func queueEvent(account string, ts time.Time) event.Event {
	return event.Event{
		Type:      event.QueueAccepted,
		Account:   account,
		Domain:    domainOf(account),
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

func TestBelowThreshold(t *testing.T) {
	m := numbermessages.New(defaultCfg)
	now := time.Now()

	for i := 0; i < defaultCfg.MaxMessages-1; i++ {
		alerts := m.Handle(queueEvent("user@domain.com", now.Add(time.Duration(i)*time.Second)))
		if len(alerts) != 0 {
			t.Fatalf("mensaje %d: no debe haber alerta antes del umbral", i+1)
		}
	}
}

func TestExactThreshold(t *testing.T) {
	m := numbermessages.New(defaultCfg)
	now := time.Now()

	var alerts []detection.Alert
	for i := 0; i < defaultCfg.MaxMessages; i++ {
		alerts = m.Handle(queueEvent("user@domain.com", now.Add(time.Duration(i)*time.Second)))
	}

	if len(alerts) != 1 {
		t.Fatalf("se esperaba 1 alerta al llegar al umbral, got %d", len(alerts))
	}
	a := alerts[0]
	if a.Action != detection.ActionSuspendAcct {
		t.Errorf("Action: got %q, want %q", a.Action, detection.ActionSuspendAcct)
	}
	if a.Account != "user@domain.com" {
		t.Errorf("Account: got %q, want %q", a.Account, "user@domain.com")
	}
	if a.Score != 80 {
		t.Errorf("Score: got %d, want 80", a.Score)
	}
	if a.Severity != detection.SeveritySuspend {
		t.Errorf("Severity: got %d, want SeveritySuspend(%d)", a.Severity, detection.SeveritySuspend)
	}
	if a.Module != "number_messages" {
		t.Errorf("Module: got %q, want %q", a.Module, "number_messages")
	}
	if len(a.Reasons) == 0 || a.Reasons[0] == "" {
		t.Error("Reasons debe contener una descripción no vacía")
	}
}

func TestWindowExpiry(t *testing.T) {
	m := numbermessages.New(defaultCfg)
	now := time.Now()

	// MaxMessages-1 mensajes al inicio de la ventana
	for i := 0; i < defaultCfg.MaxMessages-1; i++ {
		m.Handle(queueEvent("spammer@domain.com", now))
	}

	// Un mensaje llegado justo cuando los anteriores expirarán
	future := now.Add(defaultCfg.ScanTime + time.Second)
	alerts := m.Handle(queueEvent("spammer@domain.com", future))

	if len(alerts) != 0 {
		t.Fatal("los mensajes viejos debieron expirar: no debe generarse alerta")
	}
}

func TestWindowExpiryThenSuspend(t *testing.T) {
	m := numbermessages.New(defaultCfg)
	now := time.Now()

	// MaxMessages-1 mensajes viejos (fuera de la próxima ventana)
	for i := 0; i < defaultCfg.MaxMessages-1; i++ {
		m.Handle(queueEvent("spammer@domain.com", now))
	}

	// MaxMessages mensajes frescos dentro de la nueva ventana → suspensión
	future := now.Add(defaultCfg.ScanTime + time.Second)
	var alerts []detection.Alert
	for i := 0; i < defaultCfg.MaxMessages; i++ {
		alerts = m.Handle(queueEvent("spammer@domain.com", future.Add(time.Duration(i)*time.Second)))
	}

	if len(alerts) != 1 {
		t.Fatalf("deben generarse %d mensajes frescos para suspender: got %d alertas", defaultCfg.MaxMessages, len(alerts))
	}
}

func TestResetAfterSuspend(t *testing.T) {
	m := numbermessages.New(defaultCfg)
	now := time.Now()

	// Primer bloqueo
	for i := 0; i < defaultCfg.MaxMessages; i++ {
		m.Handle(queueEvent("victim@domain.com", now.Add(time.Duration(i)*time.Second)))
	}

	// Tras suspensión el contador debe reiniciarse
	later := now.Add(time.Minute)
	for i := 0; i < defaultCfg.MaxMessages-1; i++ {
		alerts := m.Handle(queueEvent("victim@domain.com", later.Add(time.Duration(i)*time.Second)))
		if len(alerts) != 0 {
			t.Fatalf("tras suspensión el contador debe reiniciarse (mensaje %d)", i+1)
		}
	}
}

func TestIgnoresEmptyAccount(t *testing.T) {
	m := numbermessages.New(defaultCfg)
	now := time.Now()

	// from=<> (bounce/NDR) — no tiene cuenta, debe ignorarse siempre
	for i := 0; i < defaultCfg.MaxMessages*2; i++ {
		ev := event.Event{
			Type:      event.QueueAccepted,
			Account:   "",
			Timestamp: now,
		}
		alerts := m.Handle(ev)
		if len(alerts) != 0 {
			t.Fatal("mensajes sin remitente (from=<>) no deben generar alertas")
		}
	}
}

func TestIgnoresNonQueueAccepted(t *testing.T) {
	m := numbermessages.New(defaultCfg)
	now := time.Now()

	otherTypes := []event.Type{
		event.AuthFailed, event.AuthSuccess,
		event.MessageSent, event.MessageBounce, event.MessageDeferred,
	}
	for _, t2 := range otherTypes {
		ev := event.Event{Type: t2, Account: "user@domain.com", Timestamp: now}
		alerts := m.Handle(ev)
		if len(alerts) != 0 {
			t.Errorf("tipo %q no debe generar alertas en NumberMessages", t2)
		}
	}
}

func TestMultipleAccounts(t *testing.T) {
	m := numbermessages.New(defaultCfg)
	now := time.Now()

	// cuenta A llega al umbral
	for i := 0; i < defaultCfg.MaxMessages; i++ {
		m.Handle(queueEvent("accountA@domain.com", now.Add(time.Duration(i)*time.Second)))
	}

	// cuenta B todavía no debe disparar alerta
	for i := 0; i < defaultCfg.MaxMessages-1; i++ {
		alerts := m.Handle(queueEvent("accountB@domain.com", now.Add(time.Duration(i)*time.Second)))
		if len(alerts) != 0 {
			t.Fatal("cuenta B no debe disparar alerta antes del umbral")
		}
	}
}

func TestDomainPropagated(t *testing.T) {
	m := numbermessages.New(defaultCfg)
	now := time.Now()

	var last []detection.Alert
	for i := 0; i < defaultCfg.MaxMessages; i++ {
		last = m.Handle(queueEvent("user@example.com", now.Add(time.Duration(i)*time.Second)))
	}
	if len(last) != 1 {
		t.Fatal("se esperaba una alerta")
	}
	if last[0].Domain != "example.com" {
		t.Errorf("Domain: got %q, want %q", last[0].Domain, "example.com")
	}
}

func TestServerPropagated(t *testing.T) {
	m := numbermessages.New(defaultCfg)
	now := time.Now()

	ev := func(i int) event.Event {
		e := queueEvent("user@domain.com", now.Add(time.Duration(i)*time.Second))
		e.Server = "zimbra-srv-01"
		return e
	}
	var last []detection.Alert
	for i := 0; i < defaultCfg.MaxMessages; i++ {
		last = m.Handle(ev(i))
	}
	if len(last) != 1 {
		t.Fatal("se esperaba una alerta")
	}
	if last[0].Server != "zimbra-srv-01" {
		t.Errorf("Server: got %q, want %q", last[0].Server, "zimbra-srv-01")
	}
}
