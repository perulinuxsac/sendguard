package queuemonitor_test

import (
	"testing"
	"time"

	"github.com/perulinux/sendguard/internal/detection"
	"github.com/perulinux/sendguard/internal/detection/queuemonitor"
	"github.com/perulinux/sendguard/internal/event"
)

var defaultCfg = queuemonitor.Config{
	Threshold: 10,
	ScanTime:  1 * time.Hour,
}

func deferredEvent(to string, ts time.Time) event.Event {
	return event.Event{
		Type:      event.MessageDeferred,
		Server:    "mail01",
		IP:        "203.0.113.1",
		Timestamp: ts,
		Extra:     map[string]string{"to": to, "relay": "mx.gmail.com[64.233.160.27]:25"},
	}
}

func TestBelowThreshold(t *testing.T) {
	m := queuemonitor.New(defaultCfg)
	now := time.Now()

	for i := 0; i < defaultCfg.Threshold-1; i++ {
		alerts := m.Handle(deferredEvent("user@gmail.com", now.Add(time.Duration(i)*time.Second)))
		if len(alerts) != 0 {
			t.Fatalf("deferral %d: no debe haber alerta antes del umbral", i+1)
		}
	}
}

func TestExactThreshold(t *testing.T) {
	m := queuemonitor.New(defaultCfg)
	now := time.Now()

	var alerts []detection.Alert
	for i := 0; i < defaultCfg.Threshold; i++ {
		alerts = m.Handle(deferredEvent("user@gmail.com", now.Add(time.Duration(i)*time.Second)))
	}

	if len(alerts) != 1 {
		t.Fatalf("se esperaba 1 alerta al llegar al umbral, got %d", len(alerts))
	}
	a := alerts[0]
	if a.Action != detection.ActionNotifyOnly {
		t.Errorf("Action: got %q, want ActionNotifyOnly", a.Action)
	}
	if a.Score != 70 {
		t.Errorf("Score: got %d, want 70", a.Score)
	}
	if a.Severity != detection.SeverityRateLimit {
		t.Errorf("Severity: got %d, want SeverityRateLimit(%d)", a.Severity, detection.SeverityRateLimit)
	}
	if a.Module != "queue_monitor" {
		t.Errorf("Module: got %q, want %q", a.Module, "queue_monitor")
	}
	if a.Domain != "gmail.com" {
		t.Errorf("Domain: got %q, want %q", a.Domain, "gmail.com")
	}
	if len(a.Reasons) == 0 || a.Reasons[0] == "" {
		t.Error("Reasons debe contener una descripción no vacía")
	}
}

func TestGroupsByDomain(t *testing.T) {
	// Deferrals a distintas direcciones del mismo dominio deben acumularse juntas.
	m := queuemonitor.New(defaultCfg)
	now := time.Now()

	addresses := []string{
		"alice@gmail.com", "bob@gmail.com", "carol@gmail.com",
		"dave@gmail.com", "eve@gmail.com", "frank@gmail.com",
		"grace@gmail.com", "heidi@gmail.com", "ivan@gmail.com",
	}

	for i, addr := range addresses {
		alerts := m.Handle(deferredEvent(addr, now.Add(time.Duration(i)*time.Second)))
		if len(alerts) != 0 {
			t.Fatalf("no debe haber alerta en deferral %d (por debajo del umbral)", i+1)
		}
	}

	// El décimo deferral (a otra dirección @gmail.com) debe disparar la alerta.
	alerts := m.Handle(deferredEvent("judy@gmail.com", now.Add(10*time.Second)))
	if len(alerts) != 1 {
		t.Fatalf("se esperaba 1 alerta al llegar al umbral con distintas direcciones del mismo dominio, got %d", len(alerts))
	}
	if alerts[0].Domain != "gmail.com" {
		t.Errorf("Domain: got %q, want %q", alerts[0].Domain, "gmail.com")
	}
}

func TestDifferentDomainsIndependent(t *testing.T) {
	m := queuemonitor.New(defaultCfg)
	now := time.Now()

	// gmail.com llega al umbral
	for i := 0; i < defaultCfg.Threshold; i++ {
		m.Handle(deferredEvent("user@gmail.com", now.Add(time.Duration(i)*time.Second)))
	}

	// hotmail.com no debe verse afectado
	for i := 0; i < defaultCfg.Threshold-1; i++ {
		alerts := m.Handle(deferredEvent("user@hotmail.com", now.Add(time.Duration(i)*time.Second)))
		if len(alerts) != 0 {
			t.Fatalf("hotmail.com no debe disparar alerta antes de su propio umbral (deferral %d)", i+1)
		}
	}
}

func TestWindowExpiry(t *testing.T) {
	m := queuemonitor.New(defaultCfg)
	now := time.Now()

	// Threshold-1 deferrals al inicio de la ventana
	for i := 0; i < defaultCfg.Threshold-1; i++ {
		m.Handle(deferredEvent("user@yahoo.com", now))
	}

	// Un deferral llegado cuando los anteriores ya expiraron
	future := now.Add(defaultCfg.ScanTime + time.Second)
	alerts := m.Handle(deferredEvent("user@yahoo.com", future))
	if len(alerts) != 0 {
		t.Fatal("deferrals viejos deben expirar: no debe generarse alerta")
	}
}

func TestWindowExpiryThenAlert(t *testing.T) {
	m := queuemonitor.New(defaultCfg)
	now := time.Now()

	// Threshold-1 deferrals viejos (fuera de la próxima ventana)
	for i := 0; i < defaultCfg.Threshold-1; i++ {
		m.Handle(deferredEvent("user@yahoo.com", now))
	}

	// Threshold deferrals frescos dentro de la nueva ventana → alerta
	future := now.Add(defaultCfg.ScanTime + time.Second)
	var alerts []detection.Alert
	for i := 0; i < defaultCfg.Threshold; i++ {
		alerts = m.Handle(deferredEvent("user@yahoo.com", future.Add(time.Duration(i)*time.Second)))
	}
	if len(alerts) != 1 {
		t.Fatalf("deferrals frescos deben generar alerta: got %d", len(alerts))
	}
}

func TestResetAfterAlert(t *testing.T) {
	m := queuemonitor.New(defaultCfg)
	now := time.Now()

	// Primera alerta
	for i := 0; i < defaultCfg.Threshold; i++ {
		m.Handle(deferredEvent("user@outlook.com", now.Add(time.Duration(i)*time.Second)))
	}

	// Tras la alerta el contador debe reiniciarse
	later := now.Add(time.Minute)
	for i := 0; i < defaultCfg.Threshold-1; i++ {
		alerts := m.Handle(deferredEvent("user@outlook.com", later.Add(time.Duration(i)*time.Second)))
		if len(alerts) != 0 {
			t.Fatalf("tras alerta el contador debe reiniciarse (deferral %d)", i+1)
		}
	}
}

func TestIgnoresNonDeferred(t *testing.T) {
	m := queuemonitor.New(defaultCfg)
	now := time.Now()

	otherTypes := []event.Type{
		event.AuthFailed, event.AuthSuccess,
		event.QueueAccepted, event.MessageSent, event.MessageBounce,
	}
	for _, t2 := range otherTypes {
		ev := event.Event{
			Type:      t2,
			Timestamp: now,
			Extra:     map[string]string{"to": "user@gmail.com"},
		}
		if len(m.Handle(ev)) != 0 {
			t.Errorf("tipo %q no debe generar alertas en QueueMonitor", t2)
		}
	}
}

func TestIgnoresEmptyTo(t *testing.T) {
	m := queuemonitor.New(defaultCfg)
	now := time.Now()

	for i := 0; i < defaultCfg.Threshold*2; i++ {
		ev := event.Event{
			Type:      event.MessageDeferred,
			Timestamp: now,
			Extra:     map[string]string{"to": ""},
		}
		if len(m.Handle(ev)) != 0 {
			t.Fatal("deferrals sin destinatario no deben generar alertas")
		}
	}
}

func TestIgnoresNilExtra(t *testing.T) {
	m := queuemonitor.New(defaultCfg)
	now := time.Now()

	for i := 0; i < defaultCfg.Threshold*2; i++ {
		ev := event.Event{
			Type:      event.MessageDeferred,
			Timestamp: now,
			Extra:     nil,
		}
		if len(m.Handle(ev)) != 0 {
			t.Fatal("deferrals sin Extra no deben generar alertas")
		}
	}
}

func TestIgnoresAddressWithoutAt(t *testing.T) {
	m := queuemonitor.New(defaultCfg)
	now := time.Now()

	for i := 0; i < defaultCfg.Threshold*2; i++ {
		ev := event.Event{
			Type:      event.MessageDeferred,
			Timestamp: now,
			Extra:     map[string]string{"to": "malformed-address"},
		}
		if len(m.Handle(ev)) != 0 {
			t.Fatal("dirección sin @ no debe generar alertas")
		}
	}
}

func TestServerPropagated(t *testing.T) {
	m := queuemonitor.New(defaultCfg)
	now := time.Now()

	ev := func(i int) event.Event {
		e := deferredEvent("user@proton.me", now.Add(time.Duration(i)*time.Second))
		e.Server = "zimbra-srv-02"
		return e
	}
	var last []detection.Alert
	for i := 0; i < defaultCfg.Threshold; i++ {
		last = m.Handle(ev(i))
	}
	if len(last) != 1 {
		t.Fatal("se esperaba una alerta")
	}
	if last[0].Server != "zimbra-srv-02" {
		t.Errorf("Server: got %q, want %q", last[0].Server, "zimbra-srv-02")
	}
}
