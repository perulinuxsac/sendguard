package authfailed_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/perulinux/sendguard/internal/detection"
	"github.com/perulinux/sendguard/internal/detection/authfailed"
	"github.com/perulinux/sendguard/internal/event"
)

var defaultCfg = authfailed.Config{
	MaxFailures: 5,
	ScanTime:    5 * time.Minute,
}

func failedEvent(ip string, ts time.Time) event.Event {
	return event.Event{
		Type:      event.AuthFailed,
		IP:        ip,
		Server:    "mail01",
		Timestamp: ts,
	}
}

func TestBelowThreshold(t *testing.T) {
	m := authfailed.New(defaultCfg)
	now := time.Now()

	for i := 0; i < defaultCfg.MaxFailures-1; i++ {
		alerts := m.Handle(failedEvent("1.2.3.4", now.Add(time.Duration(i)*time.Second)))
		if len(alerts) != 0 {
			t.Fatalf("intento %d: no debería haber alerta antes del umbral", i+1)
		}
	}
}

func TestExactThreshold(t *testing.T) {
	m := authfailed.New(defaultCfg)
	now := time.Now()

	var alerts []detection.Alert
	for i := 0; i < defaultCfg.MaxFailures; i++ {
		alerts = m.Handle(failedEvent("1.2.3.4", now.Add(time.Duration(i)*time.Second)))
	}

	if len(alerts) != 1 {
		t.Fatalf("se esperaba 1 alerta al llegar al umbral, got %d", len(alerts))
	}
	a := alerts[0]
	if a.Action != detection.ActionBlockIP {
		t.Errorf("Action: got %q, want %q", a.Action, detection.ActionBlockIP)
	}
	if a.IP != "1.2.3.4" {
		t.Errorf("IP: got %q, want %q", a.IP, "1.2.3.4")
	}
	if a.Module != "auth_failed" {
		t.Errorf("Module: got %q, want %q", a.Module, "auth_failed")
	}
	if a.Score != 60 {
		t.Errorf("Score: got %d, want 60", a.Score)
	}
	if a.Severity != detection.SeverityRateLimit {
		t.Errorf("Severity: got %d, want SeverityRateLimit(%d)", a.Severity, detection.SeverityRateLimit)
	}
	if len(a.Reasons) == 0 {
		t.Error("Reasons no debe estar vacío")
	}
}

func TestWindowExpiry(t *testing.T) {
	m := authfailed.New(defaultCfg)
	now := time.Now()

	// 4 fallos cerca del inicio de la ventana
	for i := 0; i < 4; i++ {
		m.Handle(failedEvent("5.5.5.5", now))
	}

	// 1 fallo fuera de la ventana (más antiguo que ScanTime)
	// Los 4 anteriores deberían quedar fuera de la nueva ventana
	future := now.Add(defaultCfg.ScanTime + time.Second)
	alerts := m.Handle(failedEvent("5.5.5.5", future))

	if len(alerts) != 0 {
		t.Fatal("los fallos viejos deben expirar: no debería generarse alerta")
	}
}

func TestWindowExpiryThenBlock(t *testing.T) {
	m := authfailed.New(defaultCfg)
	now := time.Now()

	// 4 fallos viejos (fuera de la siguiente ventana)
	for i := 0; i < 4; i++ {
		m.Handle(failedEvent("9.9.9.9", now))
	}

	// Ahora, 5 fallos frescos dentro de la ventana de future
	future := now.Add(defaultCfg.ScanTime + time.Second)
	var alerts []detection.Alert
	for i := 0; i < defaultCfg.MaxFailures; i++ {
		alerts = m.Handle(failedEvent("9.9.9.9", future.Add(time.Duration(i)*time.Second)))
	}

	if len(alerts) != 1 {
		t.Fatalf("deben dispararse %d fallos frescos para bloquear: got %d alertas", defaultCfg.MaxFailures, len(alerts))
	}
}

func TestResetAfterBlock(t *testing.T) {
	m := authfailed.New(defaultCfg)
	now := time.Now()

	// Primer bloqueo
	for i := 0; i < defaultCfg.MaxFailures; i++ {
		m.Handle(failedEvent("2.2.2.2", now.Add(time.Duration(i)*time.Second)))
	}

	// Después del bloqueo, la IP debería acumular desde cero.
	// MaxFailures-1 intentos nuevos → no deben generar alerta.
	later := now.Add(time.Minute)
	for i := 0; i < defaultCfg.MaxFailures-1; i++ {
		alerts := m.Handle(failedEvent("2.2.2.2", later.Add(time.Duration(i)*time.Second)))
		if len(alerts) != 0 {
			t.Fatalf("tras el bloqueo, el contador debe reiniciarse (intento %d)", i+1)
		}
	}
}

func TestIgnoresNonAuthFailed(t *testing.T) {
	m := authfailed.New(defaultCfg)
	now := time.Now()

	otherTypes := []event.Type{
		event.AuthSuccess, event.QueueAccepted, event.MessageSent,
		event.MessageBounce, event.MessageDeferred,
	}
	for _, t2 := range otherTypes {
		ev := event.Event{Type: t2, IP: "3.3.3.3", Timestamp: now}
		alerts := m.Handle(ev)
		if len(alerts) != 0 {
			t.Errorf("tipo %q no debe generar alertas en AuthFailed", t2)
		}
	}
}

func TestIgnoresEmptyIP(t *testing.T) {
	m := authfailed.New(defaultCfg)
	now := time.Now()

	for i := 0; i < defaultCfg.MaxFailures*2; i++ {
		ev := event.Event{Type: event.AuthFailed, IP: "", Timestamp: now}
		alerts := m.Handle(ev)
		if len(alerts) != 0 {
			t.Fatal("eventos sin IP no deben generar alertas")
		}
	}
}

func TestMultipleIPs(t *testing.T) {
	m := authfailed.New(defaultCfg)
	now := time.Now()

	// IP A llega al umbral
	for i := 0; i < defaultCfg.MaxFailures; i++ {
		m.Handle(failedEvent("10.0.0.1", now.Add(time.Duration(i)*time.Second)))
	}

	// IP B todavía no
	for i := 0; i < defaultCfg.MaxFailures-1; i++ {
		alerts := m.Handle(failedEvent("10.0.0.2", now.Add(time.Duration(i)*time.Second)))
		if len(alerts) != 0 {
			t.Fatal("IP B no debe disparar alerta antes del umbral")
		}
	}
}

func TestSeverityFromScore(t *testing.T) {
	cases := []struct {
		score    int
		expected detection.Severity
	}{
		{0, detection.SeverityLog},
		{29, detection.SeverityLog},
		{30, detection.SeverityWarn},
		{49, detection.SeverityWarn},
		{50, detection.SeverityRateLimit},
		{79, detection.SeverityRateLimit},
		{80, detection.SeveritySuspend},
		{100, detection.SeveritySuspend},
	}
	for _, tc := range cases {
		got := detection.SeverityFromScore(tc.score)
		if got != tc.expected {
			t.Errorf("SeverityFromScore(%d) = %d, want %d", tc.score, got, tc.expected)
		}
	}
}

func TestReasonsNotEmpty(t *testing.T) {
	m := authfailed.New(defaultCfg)
	now := time.Now()
	var last []detection.Alert
	for i := 0; i < defaultCfg.MaxFailures; i++ {
		last = m.Handle(failedEvent("7.7.7.7", now.Add(time.Duration(i)*time.Second)))
	}
	if len(last) == 0 {
		t.Fatal("se esperaba una alerta")
	}
	if len(last[0].Reasons) == 0 || last[0].Reasons[0] == "" {
		t.Error("Reasons debe contener una descripción no vacía")
	}
}

// Benchmark para verificar que el módulo es rápido con muchas IPs.
func BenchmarkHandle(b *testing.B) {
	m := authfailed.New(defaultCfg)
	now := time.Now()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ip := fmt.Sprintf("10.%d.%d.%d", i/65536%256, i/256%256, i%256)
		m.Handle(failedEvent(ip, now.Add(time.Duration(i)*time.Millisecond)))
	}
}
