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

// sentEvent simula una entrega exitosa a un dominio externo (relay público).
func sentEvent(account string, ts time.Time) event.Event {
	return event.Event{
		Type:      event.MessageSent,
		Process:   "postfix/smtp",
		Account:   account,
		Domain:    domainOf(account),
		Server:    "mail01",
		Timestamp: ts,
		Extra:     map[string]string{"to": "dest@externo.com", "relay": "mx.externo.com[203.0.113.25]:25"},
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
		alerts := m.Handle(sentEvent("user@domain.com", now.Add(time.Duration(i)*time.Second)))
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
		alerts = m.Handle(sentEvent("user@domain.com", now.Add(time.Duration(i)*time.Second)))
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
		m.Handle(sentEvent("spammer@domain.com", now))
	}

	// Un mensaje llegado justo cuando los anteriores expirarán
	future := now.Add(defaultCfg.ScanTime + time.Second)
	alerts := m.Handle(sentEvent("spammer@domain.com", future))

	if len(alerts) != 0 {
		t.Fatal("los mensajes viejos debieron expirar: no debe generarse alerta")
	}
}

func TestWindowExpiryThenSuspend(t *testing.T) {
	m := numbermessages.New(defaultCfg)
	now := time.Now()

	// MaxMessages-1 mensajes viejos (fuera de la próxima ventana)
	for i := 0; i < defaultCfg.MaxMessages-1; i++ {
		m.Handle(sentEvent("spammer@domain.com", now))
	}

	// MaxMessages mensajes frescos dentro de la nueva ventana → suspensión
	future := now.Add(defaultCfg.ScanTime + time.Second)
	var alerts []detection.Alert
	for i := 0; i < defaultCfg.MaxMessages; i++ {
		alerts = m.Handle(sentEvent("spammer@domain.com", future.Add(time.Duration(i)*time.Second)))
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
		m.Handle(sentEvent("victim@domain.com", now.Add(time.Duration(i)*time.Second)))
	}

	// Tras suspensión el contador debe reiniciarse
	later := now.Add(time.Minute)
	for i := 0; i < defaultCfg.MaxMessages-1; i++ {
		alerts := m.Handle(sentEvent("victim@domain.com", later.Add(time.Duration(i)*time.Second)))
		if len(alerts) != 0 {
			t.Fatalf("tras suspensión el contador debe reiniciarse (mensaje %d)", i+1)
		}
	}
}

func TestIgnoresEmptyAccount(t *testing.T) {
	m := numbermessages.New(defaultCfg)
	now := time.Now()

	// Entregas sin remitente correlacionado (tráfico MX entrante) deben ignorarse.
	for i := 0; i < defaultCfg.MaxMessages*2; i++ {
		ev := sentEvent("", now)
		ev.Domain = ""
		alerts := m.Handle(ev)
		if len(alerts) != 0 {
			t.Fatal("mensajes sin remitente (from=<>) no deben generar alertas")
		}
	}
}

func TestIgnoresNonMessageSent(t *testing.T) {
	m := numbermessages.New(defaultCfg)
	now := time.Now()

	otherTypes := []event.Type{
		event.AuthFailed, event.AuthSuccess,
		event.QueueAccepted, event.MessageBounce, event.MessageDeferred,
	}
	for _, t2 := range otherTypes {
		ev := sentEvent("user@domain.com", now)
		ev.Type = t2
		alerts := m.Handle(ev)
		if len(alerts) != 0 {
			t.Errorf("tipo %q no debe generar alertas en NumberMessages", t2)
		}
	}
}

// ── Solo cuentan las entregas a dominios externos ────────────────────────────

func TestIgnoresLocalLMTPDelivery(t *testing.T) {
	m := numbermessages.New(defaultCfg)
	now := time.Now()

	// Entregas a buzones locales del propio servidor (postfix/lmtp): no cuentan.
	for i := 0; i < defaultCfg.MaxMessages*2; i++ {
		ev := sentEvent("user@domain.com", now.Add(time.Duration(i)*time.Second))
		ev.Process = "postfix/lmtp"
		ev.Extra["relay"] = "mail01.domain.com[10.0.0.5]:7025"
		if alerts := m.Handle(ev); len(alerts) != 0 {
			t.Fatal("entregas lmtp (buzón local) no deben generar alertas")
		}
	}
}

func TestIgnoresInternalRelays(t *testing.T) {
	m := numbermessages.New(defaultCfg)
	now := time.Now()

	internalRelays := []string{
		"127.0.0.1[127.0.0.1]:10024",       // amavis (content filter)
		"localhost[127.0.0.1]:10025",       // re-inyección
		"mta2.interno.pe[192.168.10.4]:25", // MTA interno RFC 1918
		"relay.interno.pe[172.16.5.10]:25", // MTA interno RFC 1918
	}
	for _, relay := range internalRelays {
		for i := 0; i < defaultCfg.MaxMessages*2; i++ {
			ev := sentEvent("user@domain.com", now.Add(time.Duration(i)*time.Second))
			ev.Extra["relay"] = relay
			if alerts := m.Handle(ev); len(alerts) != 0 {
				t.Fatalf("relay interno %q no debe generar alertas", relay)
			}
		}
	}
}

func TestExternalAndInternalMixed(t *testing.T) {
	m := numbermessages.New(defaultCfg)
	now := time.Now()

	// Intercalar entregas internas: solo las externas deben acumular.
	var alerts []detection.Alert
	for i := 0; i < defaultCfg.MaxMessages; i++ {
		local := sentEvent("user@domain.com", now.Add(time.Duration(i)*time.Second))
		local.Process = "postfix/lmtp"
		m.Handle(local)
		alerts = m.Handle(sentEvent("user@domain.com", now.Add(time.Duration(i)*time.Second)))
	}
	if len(alerts) != 1 {
		t.Fatalf("las %d externas deben disparar la alerta (las locales no cuentan): got %d", defaultCfg.MaxMessages, len(alerts))
	}
}

func TestMultipleAccounts(t *testing.T) {
	m := numbermessages.New(defaultCfg)
	now := time.Now()

	// cuenta A llega al umbral
	for i := 0; i < defaultCfg.MaxMessages; i++ {
		m.Handle(sentEvent("accountA@domain.com", now.Add(time.Duration(i)*time.Second)))
	}

	// cuenta B todavía no debe disparar alerta
	for i := 0; i < defaultCfg.MaxMessages-1; i++ {
		alerts := m.Handle(sentEvent("accountB@domain.com", now.Add(time.Duration(i)*time.Second)))
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
		last = m.Handle(sentEvent("user@example.com", now.Add(time.Duration(i)*time.Second)))
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
		e := sentEvent("user@domain.com", now.Add(time.Duration(i)*time.Second))
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
