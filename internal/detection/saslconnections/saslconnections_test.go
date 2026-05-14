package saslconnections_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/perulinux/sendguard/internal/detection"
	"github.com/perulinux/sendguard/internal/detection/saslconnections"
	"github.com/perulinux/sendguard/internal/event"
)

var defaultCfg = saslconnections.Config{
	Max:      5,
	ScanTime: 5 * time.Minute,
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

func TestBelowThreshold(t *testing.T) {
	m := saslconnections.New(defaultCfg)
	now := time.Now()

	for i := 0; i < defaultCfg.Max-1; i++ {
		alerts := m.Handle(authEvent("user@domain.com", "1.2.3.4", now.Add(time.Duration(i)*time.Second)))
		if len(alerts) != 0 {
			t.Fatalf("conexión %d: no debe haber alerta antes del umbral", i+1)
		}
	}
}

func TestExactThreshold(t *testing.T) {
	m := saslconnections.New(defaultCfg)
	now := time.Now()

	var alerts []detection.Alert
	for i := 0; i < defaultCfg.Max; i++ {
		ip := fmt.Sprintf("10.0.0.%d", i+1)
		alerts = m.Handle(authEvent("user@domain.com", ip, now.Add(time.Duration(i)*time.Second)))
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
	if a.Score != 65 {
		t.Errorf("Score: got %d, want 65", a.Score)
	}
	if a.Severity != detection.SeverityRateLimit {
		t.Errorf("Severity: got %d, want SeverityRateLimit(%d)", a.Severity, detection.SeverityRateLimit)
	}
	if a.Module != "sasl_connections" {
		t.Errorf("Module: got %q, want %q", a.Module, "sasl_connections")
	}
	if len(a.Reasons) == 0 || a.Reasons[0] == "" {
		t.Error("Reasons debe contener una descripción no vacía")
	}
}

func TestIPPropagatedFromTriggeringConnection(t *testing.T) {
	m := saslconnections.New(defaultCfg)
	now := time.Now()

	// Conectar desde varias IPs distintas (botnet)
	ips := []string{"1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4", "5.5.5.5"}
	var alerts []detection.Alert
	for i, ip := range ips {
		alerts = m.Handle(authEvent("victim@domain.com", ip, now.Add(time.Duration(i)*time.Second)))
	}

	if len(alerts) != 1 {
		t.Fatalf("se esperaba 1 alerta, got %d", len(alerts))
	}
	// La IP debe ser la de la conexión que cruzó el umbral (la última)
	if alerts[0].IP != "5.5.5.5" {
		t.Errorf("IP: got %q, want %q (última conexión)", alerts[0].IP, "5.5.5.5")
	}
}

func TestWindowExpiry(t *testing.T) {
	m := saslconnections.New(defaultCfg)
	now := time.Now()

	// Max-1 conexiones en el inicio de la ventana
	for i := 0; i < defaultCfg.Max-1; i++ {
		m.Handle(authEvent("user@domain.com", "1.2.3.4", now))
	}

	// Una conexión pasada la ventana: las anteriores deben expirar
	future := now.Add(defaultCfg.ScanTime + time.Second)
	alerts := m.Handle(authEvent("user@domain.com", "1.2.3.4", future))

	if len(alerts) != 0 {
		t.Fatal("las conexiones viejas debieron expirar: no debe generarse alerta")
	}
}

func TestWindowExpiryThenSuspend(t *testing.T) {
	m := saslconnections.New(defaultCfg)
	now := time.Now()

	// Max-1 conexiones viejas (fuera de la próxima ventana)
	for i := 0; i < defaultCfg.Max-1; i++ {
		m.Handle(authEvent("user@domain.com", "1.2.3.4", now))
	}

	// Max conexiones frescas → suspensión
	future := now.Add(defaultCfg.ScanTime + time.Second)
	var alerts []detection.Alert
	for i := 0; i < defaultCfg.Max; i++ {
		alerts = m.Handle(authEvent("user@domain.com", "5.6.7.8", future.Add(time.Duration(i)*time.Second)))
	}

	if len(alerts) != 1 {
		t.Fatalf("deben generarse %d conexiones frescas para suspender: got %d alertas", defaultCfg.Max, len(alerts))
	}
}

func TestResetAfterSuspend(t *testing.T) {
	m := saslconnections.New(defaultCfg)
	now := time.Now()

	// Primera suspensión
	for i := 0; i < defaultCfg.Max; i++ {
		m.Handle(authEvent("victim@domain.com", "1.2.3.4", now.Add(time.Duration(i)*time.Second)))
	}

	// Tras suspensión el contador debe reiniciarse
	later := now.Add(time.Minute)
	for i := 0; i < defaultCfg.Max-1; i++ {
		alerts := m.Handle(authEvent("victim@domain.com", "1.2.3.4", later.Add(time.Duration(i)*time.Second)))
		if len(alerts) != 0 {
			t.Fatalf("tras suspensión el contador debe reiniciarse (conexión %d)", i+1)
		}
	}
}

func TestIgnoresEmptyAccount(t *testing.T) {
	m := saslconnections.New(defaultCfg)
	now := time.Now()

	for i := 0; i < defaultCfg.Max*2; i++ {
		ev := event.Event{
			Type:      event.AuthSuccess,
			Account:   "",
			IP:        "1.2.3.4",
			Timestamp: now,
		}
		if len(m.Handle(ev)) != 0 {
			t.Fatal("eventos sin cuenta no deben generar alertas")
		}
	}
}

func TestIgnoresNonAuthSuccess(t *testing.T) {
	m := saslconnections.New(defaultCfg)
	now := time.Now()

	otherTypes := []event.Type{
		event.AuthFailed, event.QueueAccepted,
		event.MessageSent, event.MessageBounce, event.MessageDeferred,
	}
	for _, t2 := range otherTypes {
		ev := event.Event{Type: t2, Account: "user@domain.com", IP: "1.2.3.4", Timestamp: now}
		if len(m.Handle(ev)) != 0 {
			t.Errorf("tipo %q no debe generar alertas en SaslConnections", t2)
		}
	}
}

func TestMultipleAccountsIndependent(t *testing.T) {
	m := saslconnections.New(defaultCfg)
	now := time.Now()

	// cuenta A llega al umbral
	for i := 0; i < defaultCfg.Max; i++ {
		m.Handle(authEvent("accountA@domain.com", "1.2.3.4", now.Add(time.Duration(i)*time.Second)))
	}

	// cuenta B no debe verse afectada
	for i := 0; i < defaultCfg.Max-1; i++ {
		alerts := m.Handle(authEvent("accountB@domain.com", "5.6.7.8", now.Add(time.Duration(i)*time.Second)))
		if len(alerts) != 0 {
			t.Fatal("cuenta B no debe disparar alerta antes del umbral")
		}
	}
}

func TestBotsFromDifferentIPs(t *testing.T) {
	// Caso real: botnet con una cuenta comprometida, cada bot desde IP distinta
	m := saslconnections.New(defaultCfg)
	now := time.Now()

	var alerts []detection.Alert
	for i := 0; i < defaultCfg.Max; i++ {
		ip := fmt.Sprintf("203.0.113.%d", i+1) // IPs distintas, misma cuenta
		alerts = m.Handle(authEvent("compromised@domain.com", ip, now.Add(time.Duration(i)*time.Second)))
	}

	if len(alerts) != 1 {
		t.Fatal("botnet desde IPs distintas con la misma cuenta debe detectarse")
	}
	if alerts[0].Account != "compromised@domain.com" {
		t.Errorf("Account incorrecto: %q", alerts[0].Account)
	}
}
