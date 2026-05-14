package domaindiscovery_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/perulinux/sendguard/internal/detection"
	"github.com/perulinux/sendguard/internal/detection/domaindiscovery"
	"github.com/perulinux/sendguard/internal/event"
)

var defaultCfg = domaindiscovery.Config{
	MaxDomains: 5,
	ScanTime:   10 * time.Minute,
}

func failedEvent(ip, account string, ts time.Time) event.Event {
	return event.Event{
		Type:      event.AuthFailed,
		IP:        ip,
		Account:   account,
		Server:    "mail01",
		Timestamp: ts,
	}
}

func TestBelowThreshold(t *testing.T) {
	m := domaindiscovery.New(defaultCfg)
	now := time.Now()

	for i := 0; i < defaultCfg.MaxDomains-1; i++ {
		account := fmt.Sprintf("user@domain%d.com", i)
		alerts := m.Handle(failedEvent("1.2.3.4", account, now.Add(time.Duration(i)*time.Second)))
		if len(alerts) != 0 {
			t.Fatalf("dominio %d: no debe haber alerta antes del umbral", i+1)
		}
	}
}

func TestExactThreshold(t *testing.T) {
	m := domaindiscovery.New(defaultCfg)
	now := time.Now()

	var alerts []detection.Alert
	for i := 0; i < defaultCfg.MaxDomains; i++ {
		account := fmt.Sprintf("user@domain%d.com", i)
		alerts = m.Handle(failedEvent("1.2.3.4", account, now.Add(time.Duration(i)*time.Second)))
	}

	if len(alerts) != 1 {
		t.Fatalf("se esperaba 1 alerta al llegar al umbral, got %d", len(alerts))
	}
	a := alerts[0]
	if a.Action != detection.ActionBlockIP {
		t.Errorf("Action: got %q, want ActionBlockIP", a.Action)
	}
	if a.Score != 75 {
		t.Errorf("Score: got %d, want 75", a.Score)
	}
	if a.Severity != detection.SeverityRateLimit {
		t.Errorf("Severity: got %d, want SeverityRateLimit(%d)", a.Severity, detection.SeverityRateLimit)
	}
	if a.Module != "domain_discovery" {
		t.Errorf("Module: got %q, want %q", a.Module, "domain_discovery")
	}
	if a.IP != "1.2.3.4" {
		t.Errorf("IP: got %q, want %q", a.IP, "1.2.3.4")
	}
	if len(a.Reasons) == 0 || a.Reasons[0] == "" {
		t.Error("Reasons debe contener una descripción no vacía")
	}
}

func TestSameDomainNotCounted(t *testing.T) {
	// Muchos fallos contra el mismo dominio no deben disparar la alerta.
	m := domaindiscovery.New(defaultCfg)
	now := time.Now()

	for i := 0; i < defaultCfg.MaxDomains*3; i++ {
		account := fmt.Sprintf("user%d@samedomain.com", i)
		alerts := m.Handle(failedEvent("1.2.3.4", account, now.Add(time.Duration(i)*time.Second)))
		if len(alerts) != 0 {
			t.Fatalf("fallo %d: mismo dominio no debe disparar alerta de domain_discovery", i+1)
		}
	}
}

func TestWindowExpiry(t *testing.T) {
	m := domaindiscovery.New(defaultCfg)
	now := time.Now()

	// MaxDomains-1 dominios distintos al inicio de la ventana.
	for i := 0; i < defaultCfg.MaxDomains-1; i++ {
		account := fmt.Sprintf("user@domain%d.com", i)
		m.Handle(failedEvent("1.2.3.4", account, now))
	}

	// Un nuevo dominio llegado cuando la ventana ya expiró → nueva ventana, sin alerta.
	future := now.Add(defaultCfg.ScanTime + time.Second)
	alerts := m.Handle(failedEvent("1.2.3.4", "user@fresh-domain.com", future))
	if len(alerts) != 0 {
		t.Fatal("ventana expirada: debe iniciarse nueva ventana, sin alerta")
	}
}

func TestWindowExpiryThenAlert(t *testing.T) {
	m := domaindiscovery.New(defaultCfg)
	now := time.Now()

	// Ventana antigua: MaxDomains-1 dominios (no dispara).
	for i := 0; i < defaultCfg.MaxDomains-1; i++ {
		m.Handle(failedEvent("1.2.3.4", fmt.Sprintf("u@old%d.com", i), now))
	}

	// Nueva ventana: MaxDomains dominios frescos → alerta.
	future := now.Add(defaultCfg.ScanTime + time.Second)
	var alerts []detection.Alert
	for i := 0; i < defaultCfg.MaxDomains; i++ {
		alerts = m.Handle(failedEvent("1.2.3.4", fmt.Sprintf("u@new%d.com", i), future.Add(time.Duration(i)*time.Second)))
	}
	if len(alerts) != 1 {
		t.Fatalf("nueva ventana con %d dominios frescos debe generar alerta: got %d", defaultCfg.MaxDomains, len(alerts))
	}
}

func TestResetAfterAlert(t *testing.T) {
	m := domaindiscovery.New(defaultCfg)
	now := time.Now()

	// Primera alerta.
	for i := 0; i < defaultCfg.MaxDomains; i++ {
		m.Handle(failedEvent("1.2.3.4", fmt.Sprintf("user@domain%d.com", i), now.Add(time.Duration(i)*time.Second)))
	}

	// Tras la alerta, el contador debe reiniciarse: MaxDomains-1 dominios nuevos → sin alerta.
	later := now.Add(time.Minute)
	for i := 0; i < defaultCfg.MaxDomains-1; i++ {
		alerts := m.Handle(failedEvent("1.2.3.4", fmt.Sprintf("user@reset%d.com", i), later.Add(time.Duration(i)*time.Second)))
		if len(alerts) != 0 {
			t.Fatalf("tras alerta el contador debe reiniciarse (dominio %d)", i+1)
		}
	}
}

func TestMultipleIPsIndependent(t *testing.T) {
	m := domaindiscovery.New(defaultCfg)
	now := time.Now()

	// IP A llega al umbral.
	for i := 0; i < defaultCfg.MaxDomains; i++ {
		m.Handle(failedEvent("1.1.1.1", fmt.Sprintf("user@domainA%d.com", i), now.Add(time.Duration(i)*time.Second)))
	}

	// IP B no debe verse afectada.
	for i := 0; i < defaultCfg.MaxDomains-1; i++ {
		alerts := m.Handle(failedEvent("2.2.2.2", fmt.Sprintf("user@domainB%d.com", i), now.Add(time.Duration(i)*time.Second)))
		if len(alerts) != 0 {
			t.Fatal("IP B no debe disparar alerta antes de su propio umbral")
		}
	}
}

func TestIgnoresNonAuthFailed(t *testing.T) {
	m := domaindiscovery.New(defaultCfg)
	now := time.Now()

	otherTypes := []event.Type{
		event.AuthSuccess, event.QueueAccepted,
		event.MessageSent, event.MessageBounce, event.MessageDeferred,
	}
	for _, t2 := range otherTypes {
		ev := event.Event{
			Type:      t2,
			IP:        "1.2.3.4",
			Account:   "user@domain.com",
			Timestamp: now,
		}
		if len(m.Handle(ev)) != 0 {
			t.Errorf("tipo %q no debe generar alertas en DomainDiscovery", t2)
		}
	}
}

func TestIgnoresEmptyIP(t *testing.T) {
	m := domaindiscovery.New(defaultCfg)
	now := time.Now()

	for i := 0; i < defaultCfg.MaxDomains*2; i++ {
		ev := event.Event{
			Type:      event.AuthFailed,
			IP:        "",
			Account:   fmt.Sprintf("user@domain%d.com", i),
			Timestamp: now,
		}
		if len(m.Handle(ev)) != 0 {
			t.Fatal("eventos sin IP no deben generar alertas")
		}
	}
}

func TestIgnoresEmptyAccount(t *testing.T) {
	m := domaindiscovery.New(defaultCfg)
	now := time.Now()

	for i := 0; i < defaultCfg.MaxDomains*2; i++ {
		ev := event.Event{
			Type:      event.AuthFailed,
			IP:        "1.2.3.4",
			Account:   "",
			Timestamp: now,
		}
		if len(m.Handle(ev)) != 0 {
			t.Fatal("eventos sin Account no deben generar alertas")
		}
	}
}

func TestIgnoresAccountWithoutAt(t *testing.T) {
	m := domaindiscovery.New(defaultCfg)
	now := time.Now()

	for i := 0; i < defaultCfg.MaxDomains*2; i++ {
		ev := event.Event{
			Type:      event.AuthFailed,
			IP:        "1.2.3.4",
			Account:   "user-without-at-sign",
			Timestamp: now,
		}
		if len(m.Handle(ev)) != 0 {
			t.Fatal("cuenta sin @ no debe generar alertas")
		}
	}
}

func TestServerPropagated(t *testing.T) {
	m := domaindiscovery.New(defaultCfg)
	now := time.Now()

	var last []detection.Alert
	for i := 0; i < defaultCfg.MaxDomains; i++ {
		ev := failedEvent("1.2.3.4", fmt.Sprintf("user@domain%d.com", i), now.Add(time.Duration(i)*time.Second))
		ev.Server = "zimbra-srv-03"
		last = m.Handle(ev)
	}
	if len(last) != 1 {
		t.Fatal("se esperaba una alerta")
	}
	if last[0].Server != "zimbra-srv-03" {
		t.Errorf("Server: got %q, want %q", last[0].Server, "zimbra-srv-03")
	}
}
