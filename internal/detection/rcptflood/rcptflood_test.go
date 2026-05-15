package rcptflood_test

import (
	"testing"
	"time"

	"github.com/perulinux/sendguard/internal/detection"
	"github.com/perulinux/sendguard/internal/detection/rcptflood"
	"github.com/perulinux/sendguard/internal/event"
)

var defaultCfg = rcptflood.Config{
	MaxRecipients: 5,
	ScanTime:      5 * time.Minute,
}

func rcptEv(ip, account string, ts time.Time) event.Event {
	return event.Event{
		Type:      event.RecipientAdded,
		IP:        ip,
		Account:   account,
		Domain:    "example.com",
		Server:    "mail01",
		Timestamp: ts,
	}
}

func TestBelowThreshold(t *testing.T) {
	m := rcptflood.New(defaultCfg)
	now := time.Now()

	for i := 0; i < defaultCfg.MaxRecipients-1; i++ {
		alerts := m.Handle(rcptEv("1.2.3.4", "spammer@example.com", now.Add(time.Duration(i)*time.Second)))
		if len(alerts) != 0 {
			t.Fatalf("destinatario %d: no debe haber alerta antes del umbral", i+1)
		}
	}
}

func TestAtThreshold(t *testing.T) {
	m := rcptflood.New(defaultCfg)
	now := time.Now()

	var alerts []detection.Alert
	for i := 0; i < defaultCfg.MaxRecipients; i++ {
		alerts = m.Handle(rcptEv("10.0.0.1", "flood@example.com", now.Add(time.Duration(i)*time.Second)))
	}

	if len(alerts) != 2 {
		t.Fatalf("got %d alertas, want 2 (BlockIP + SuspendAcct)", len(alerts))
	}

	actions := map[detection.Action]bool{}
	for _, a := range alerts {
		actions[a.Action] = true
		if a.IP != "10.0.0.1" {
			t.Errorf("IP: got %q, want 10.0.0.1", a.IP)
		}
		if a.Module != "rcpt_flood" {
			t.Errorf("Module: got %q, want rcpt_flood", a.Module)
		}
		if a.Score != 90 {
			t.Errorf("Score: got %d, want 90", a.Score)
		}
		if len(a.Reasons) == 0 {
			t.Error("Reasons no debe estar vacío")
		}
	}

	if !actions[detection.ActionBlockIP] {
		t.Error("debe emitir ActionBlockIP")
	}
	if !actions[detection.ActionSuspendAcct] {
		t.Error("debe emitir ActionSuspendAcct")
	}
}

func TestSuspendAcctOmitedWhenAccountEmpty(t *testing.T) {
	m := rcptflood.New(defaultCfg)
	now := time.Now()

	var alerts []detection.Alert
	for i := 0; i < defaultCfg.MaxRecipients; i++ {
		alerts = m.Handle(rcptEv("10.0.0.2", "", now.Add(time.Duration(i)*time.Second)))
	}

	if len(alerts) != 1 {
		t.Fatalf("sin Account: got %d alertas, want 1 (solo BlockIP)", len(alerts))
	}
	if alerts[0].Action != detection.ActionBlockIP {
		t.Errorf("Action: got %q, want ActionBlockIP", alerts[0].Action)
	}
}

func TestWindowExpiry(t *testing.T) {
	m := rcptflood.New(defaultCfg)
	now := time.Now()

	for i := 0; i < defaultCfg.MaxRecipients-1; i++ {
		m.Handle(rcptEv("5.5.5.5", "u@d.com", now.Add(time.Duration(i)*time.Second)))
	}

	// Evento fuera de ventana: el contador debe reiniciarse.
	future := now.Add(defaultCfg.ScanTime + time.Second)
	alerts := m.Handle(rcptEv("5.5.5.5", "u@d.com", future))
	if len(alerts) != 0 {
		t.Fatal("eventos viejos deben expirar: no debería generarse alerta")
	}
}

func TestResetAfterAlert(t *testing.T) {
	m := rcptflood.New(defaultCfg)
	now := time.Now()

	for i := 0; i < defaultCfg.MaxRecipients; i++ {
		m.Handle(rcptEv("7.7.7.7", "u@d.com", now.Add(time.Duration(i)*time.Second)))
	}

	// Tras la alerta la IP se resetea.
	later := now.Add(time.Minute)
	for i := 0; i < defaultCfg.MaxRecipients-1; i++ {
		alerts := m.Handle(rcptEv("7.7.7.7", "u@d.com", later.Add(time.Duration(i)*time.Second)))
		if len(alerts) != 0 {
			t.Error("tras el reset, MaxRecipients-1 no debe generar alerta")
		}
	}
}

func TestMultipleIPsIndependent(t *testing.T) {
	m := rcptflood.New(defaultCfg)
	now := time.Now()

	// IP A llega al umbral
	for i := 0; i < defaultCfg.MaxRecipients; i++ {
		m.Handle(rcptEv("100.0.0.1", "a@d.com", now.Add(time.Duration(i)*time.Second)))
	}

	// IP B con MaxRecipients-1 → sin alerta
	for i := 0; i < defaultCfg.MaxRecipients-1; i++ {
		alerts := m.Handle(rcptEv("100.0.0.2", "b@d.com", now.Add(time.Duration(i)*time.Second)))
		if len(alerts) != 0 {
			t.Fatalf("IP B no debe alertar antes del umbral (intento %d)", i+1)
		}
	}
}

func TestIgnoresNonRecipientAdded(t *testing.T) {
	m := rcptflood.New(defaultCfg)
	now := time.Now()

	for _, evType := range []event.Type{event.AuthFailed, event.AuthSuccess, event.QueueAccepted, event.MessageSent} {
		ev := event.Event{Type: evType, IP: "1.1.1.1", Account: "u@d.com", Timestamp: now}
		if alerts := m.Handle(ev); len(alerts) != 0 {
			t.Errorf("tipo %q no debe generar alertas en rcpt_flood", evType)
		}
	}
}

func TestIgnoresEmptyIP(t *testing.T) {
	m := rcptflood.New(defaultCfg)
	now := time.Now()
	for i := 0; i < defaultCfg.MaxRecipients*2; i++ {
		ev := event.Event{Type: event.RecipientAdded, IP: "", Account: "u@d.com", Timestamp: now}
		if alerts := m.Handle(ev); len(alerts) != 0 {
			t.Fatal("IP vacía no debe generar alerta")
		}
	}
}

func TestSeverity(t *testing.T) {
	m := rcptflood.New(defaultCfg)
	now := time.Now()

	var last []detection.Alert
	for i := 0; i < defaultCfg.MaxRecipients; i++ {
		last = m.Handle(rcptEv("8.8.8.8", "s@d.com", now.Add(time.Duration(i)*time.Second)))
	}
	for _, a := range last {
		if a.Severity != detection.SeveritySuspend {
			t.Errorf("Severity: got %d, want SeveritySuspend(%d)", a.Severity, detection.SeveritySuspend)
		}
	}
}
