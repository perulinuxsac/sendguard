package bouncerate

import (
	"testing"
	"time"

	"github.com/perulinux/sendguard/internal/detection"
	"github.com/perulinux/sendguard/internal/event"
)

func newModule(max int, window time.Duration) *Module {
	return New(Config{MaxBounces: max, ScanTime: window})
}

func bounceEv(account string, ts time.Time) event.Event {
	return event.Event{
		Type:      event.MessageBounce,
		Account:   account,
		Domain:    "example.com",
		Timestamp: ts,
	}
}

func TestNameEsCorrecto(t *testing.T) {
	if got := newModule(5, time.Minute).Name(); got != "bounce_rate" {
		t.Errorf("Name: got %q, want bounce_rate", got)
	}
}

func TestIgnoraEventosNoRebote(t *testing.T) {
	m := newModule(3, time.Minute)
	otros := []event.Type{event.AuthFailed, event.AuthSuccess, event.QueueAccepted, event.MessageSent}
	for _, typ := range otros {
		ev := event.Event{Type: typ, Account: "user@example.com", Timestamp: time.Now()}
		if alerts := m.Handle(ev); len(alerts) != 0 {
			t.Errorf("tipo %q no debe generar alertas, got %d", typ, len(alerts))
		}
	}
}

func TestIgnoraReboteSinCuenta(t *testing.T) {
	m := newModule(3, time.Minute)
	ev := event.Event{Type: event.MessageBounce, Account: "", Timestamp: time.Now()}
	if alerts := m.Handle(ev); len(alerts) != 0 {
		t.Errorf("sin cuenta: got %d alertas, want 0", len(alerts))
	}
}

func TestNoAlertaBajoUmbral(t *testing.T) {
	m := newModule(5, time.Minute)
	now := time.Now()
	for i := 0; i < 4; i++ {
		alerts := m.Handle(bounceEv("user@example.com", now.Add(time.Duration(i)*time.Second)))
		if len(alerts) != 0 {
			t.Errorf("iteración %d: got %d alertas antes de umbral, want 0", i, len(alerts))
		}
	}
}

func TestAlertaAlAlcanzarUmbral(t *testing.T) {
	m := newModule(5, time.Minute)
	now := time.Now()
	var alerts []detection.Alert
	for i := 0; i < 5; i++ {
		alerts = m.Handle(bounceEv("user@example.com", now.Add(time.Duration(i)*time.Second)))
	}
	if len(alerts) != 1 {
		t.Fatalf("got %d alertas al umbral, want 1", len(alerts))
	}
	a := alerts[0]
	if a.Action != detection.ActionSuspendAcct {
		t.Errorf("Action: got %q, want suspend_account", a.Action)
	}
	if a.Account != "user@example.com" {
		t.Errorf("Account: got %q, want user@example.com", a.Account)
	}
	if a.Score < 80 {
		t.Errorf("Score: got %d, debe ser >= 80 para SeveritySuspend", a.Score)
	}
	if a.Severity != detection.SeveritySuspend {
		t.Errorf("Severity: got %d, want SeveritySuspend", a.Severity)
	}
}

func TestRebotesExpiradosNoContabilizan(t *testing.T) {
	m := newModule(3, time.Minute)
	now := time.Now()

	// 2 rebotes hace 2 minutos (fuera de ventana)
	m.Handle(bounceEv("user@example.com", now.Add(-2*time.Minute)))
	m.Handle(bounceEv("user@example.com", now.Add(-2*time.Minute)))

	// 2 rebotes ahora (dentro de ventana) — total en ventana = 2, umbral = 3, sin alerta.
	for i := 0; i < 2; i++ {
		alerts := m.Handle(bounceEv("user@example.com", now.Add(time.Duration(i)*time.Second)))
		if len(alerts) != 0 {
			t.Errorf("rebotes expirados no deben contar: got %d alertas", len(alerts))
		}
	}
}

func TestAlertaReiniciaVentana(t *testing.T) {
	m := newModule(3, time.Minute)
	now := time.Now()

	// Disparar primera alerta.
	for i := 0; i < 3; i++ {
		m.Handle(bounceEv("user@example.com", now.Add(time.Duration(i)*time.Second)))
	}

	// Después de la alerta, los contadores se reinician.
	// 2 rebotes nuevos no deben generar alerta.
	for i := 0; i < 2; i++ {
		alerts := m.Handle(bounceEv("user@example.com", now.Add(time.Duration(10+i)*time.Second)))
		if len(alerts) != 0 {
			t.Errorf("después de alerta: got %d alertas con contador reiniciado", len(alerts))
		}
	}
}

func TestCuentasIndependientes(t *testing.T) {
	m := newModule(3, time.Minute)
	now := time.Now()

	// user1 acumula 3 rebotes (umbral).
	var alertas []detection.Alert
	for i := 0; i < 3; i++ {
		alertas = m.Handle(bounceEv("user1@example.com", now.Add(time.Duration(i)*time.Second)))
	}
	if len(alertas) != 1 {
		t.Fatalf("user1: got %d alertas, want 1", len(alertas))
	}

	// user2 solo tiene 2 rebotes — no debe alertar.
	for i := 0; i < 2; i++ {
		alertas = m.Handle(bounceEv("user2@example.com", now.Add(time.Duration(i)*time.Second)))
		if len(alertas) != 0 {
			t.Errorf("user2: got %d alertas sin alcanzar umbral", len(alertas))
		}
	}
}

func TestAlertaContieneRazones(t *testing.T) {
	m := newModule(3, time.Minute)
	now := time.Now()

	var alerts []detection.Alert
	for i := 0; i < 3; i++ {
		alerts = m.Handle(bounceEv("user@example.com", now.Add(time.Duration(i)*time.Second)))
	}
	if len(alerts) == 0 {
		t.Fatal("no se generaron alertas")
	}
	if len(alerts[0].Reasons) == 0 {
		t.Error("alerta debe incluir al menos una razón")
	}
}

func TestModuloNombre(t *testing.T) {
	m := newModule(5, time.Minute)
	if m.Name() != "bounce_rate" {
		t.Errorf("Name: got %q, want bounce_rate", m.Name())
	}
}
