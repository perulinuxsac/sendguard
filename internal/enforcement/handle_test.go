package enforcement

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/perulinux/sendguard/internal/audit"
	"github.com/perulinux/sendguard/internal/detection"
	"github.com/perulinux/sendguard/internal/store"
)

// captureNotifier registra las alertas recibidas para verificación en tests.
type captureNotifier struct {
	alerts []detection.Alert
}

func (n *captureNotifier) Notify(_ context.Context, a detection.Alert) error {
	n.alerts = append(n.alerts, a)
	return nil
}

func openTestStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// ── handle — ActionNotifyOnly ────────────────────────────────────────────────

func TestHandleNotifyOnly(t *testing.T) {
	n := &captureNotifier{}
	e := New(Config{Notifier: n})

	e.handle(context.Background(), detection.Alert{
		Module: "test", Action: detection.ActionNotifyOnly, Timestamp: time.Now(),
	})

	if len(n.alerts) != 1 {
		t.Errorf("ActionNotifyOnly debe llamar al notifier: got %d alerts", len(n.alerts))
	}
}

func TestHandleNotifyOnlyConAuditLog(t *testing.T) {
	var buf bytes.Buffer
	n := &captureNotifier{}
	e := New(Config{Notifier: n, AuditLog: audit.NewWithWriter(&buf)})

	e.handle(context.Background(), detection.Alert{
		Module: "test", Action: detection.ActionNotifyOnly, Timestamp: time.Now(),
	})

	if buf.Len() == 0 {
		t.Error("AuditLog debe tener contenido tras handle")
	}
}

// ── handle — ActionBlockIP early returns ────────────────────────────────────

func TestHandleBlockIPVacia(t *testing.T) {
	e := New(Config{})

	e.handle(context.Background(), detection.Alert{
		Module: "test", Action: detection.ActionBlockIP, IP: "",
	})

	if len(e.BlockedIPs()) != 0 {
		t.Error("IP vacía no debe generar ban")
	}
}

// ── handle — ActionSuspendAcct early return ──────────────────────────────────

func TestHandleSuspendAcctVacia(t *testing.T) {
	e := New(Config{})

	e.handle(context.Background(), detection.Alert{
		Module: "test", Action: detection.ActionSuspendAcct, Account: "",
	})

	if e.Stats().SuspensionsTotal != 0 {
		t.Error("cuenta vacía no debe generar suspensión")
	}
}

// ── handle — ActionRateLimit early returns ───────────────────────────────────

func TestHandleRateLimitSinCuenta(t *testing.T) {
	e := New(Config{PostfixSbin: "/tmp", PostfixConf: "/tmp"})

	e.handle(context.Background(), detection.Alert{
		Module: "test", Action: detection.ActionRateLimit, Account: "",
	})

	if e.Stats().RateLimitsTotal != 0 {
		t.Error("cuenta vacía no debe aplicar rate-limit")
	}
}

func TestHandleRateLimitSinPostfix(t *testing.T) {
	e := New(Config{PostfixSbin: "", PostfixConf: ""})

	e.handle(context.Background(), detection.Alert{
		Module: "test", Action: detection.ActionRateLimit, Account: "user@domain.com",
	})

	if e.Stats().RateLimitsTotal != 0 {
		t.Error("sin PostfixSbin no debe aplicar rate-limit")
	}
}

// ── handle — ActionPurgeQueue early returns ──────────────────────────────────

func TestHandlePurgeQueueSinDominio(t *testing.T) {
	e := New(Config{PostfixSbin: "/tmp", PostfixConf: "/tmp"})

	e.handle(context.Background(), detection.Alert{
		Module: "test", Action: detection.ActionPurgeQueue, Domain: "",
	})
}

func TestHandlePurgeQueueSinPostfix(t *testing.T) {
	e := New(Config{PostfixSbin: "", PostfixConf: ""})

	e.handle(context.Background(), detection.Alert{
		Module: "test", Action: detection.ActionPurgeQueue, Domain: "example.com",
	})
}

// ── Block / Unblock ──────────────────────────────────────────────────────────

func TestBlockIPInvalida(t *testing.T) {
	e := New(Config{})
	if err := e.Block(context.Background(), "no-es-ip"); err == nil {
		t.Error("Block con IP inválida debe retornar error")
	}
}

func TestBlockIPv6Rechazada(t *testing.T) {
	e := New(Config{})
	if err := e.Block(context.Background(), "::1"); err == nil {
		t.Error("Block con IPv6 debe retornar error")
	}
}

func TestUnblockIPInvalida(t *testing.T) {
	e := New(Config{})
	if err := e.Unblock(context.Background(), "no-es-ip"); err == nil {
		t.Error("Unblock con IP inválida debe retornar error")
	}
}

// ── loadBansFromStore ────────────────────────────────────────────────────────

func TestLoadExistingBansDesdeStore(t *testing.T) {
	s := openTestStore(t)

	expiry := time.Now().Add(time.Hour)
	s.SaveBan("1.2.3.4", "authfailed", expiry)
	s.SaveBan("5.6.7.8", "numbermessages", expiry)

	e := New(Config{BanSeconds: 3600, Store: s})
	e.LoadExistingBans(context.Background())

	blocked := e.BlockedIPs()
	if len(blocked) != 2 {
		t.Fatalf("esperado 2 IPs restauradas desde store, got %d", len(blocked))
	}
}

func TestLoadExistingBansStoreVacio(t *testing.T) {
	s := openTestStore(t)

	// Aislar de un firewalld real que pudiera estar en el servidor de test.
	// Con store vacío el Enforcer cae al fallback de firewalld; sin firewall-cmd
	// en PATH el fallback loguea un warning y no carga ninguna IP.
	t.Setenv("PATH", t.TempDir())

	e := New(Config{BanSeconds: 3600, Store: s})
	e.LoadExistingBans(context.Background())

	if len(e.BlockedIPs()) != 0 {
		t.Error("store vacío sin firewalld accesible: esperado 0 IPs")
	}
}

func TestLoadExistingBansStoreExcluirExpirados(t *testing.T) {
	s := openTestStore(t)

	s.SaveBan("1.1.1.1", "test", time.Now().Add(-time.Hour)) // expirado
	s.SaveBan("2.2.2.2", "test", time.Now().Add(time.Hour))  // vigente

	e := New(Config{BanSeconds: 3600, Store: s})
	e.LoadExistingBans(context.Background())

	blocked := e.BlockedIPs()
	if len(blocked) != 1 || blocked[0].IP != "2.2.2.2" {
		t.Fatalf("solo debe restaurar bans vigentes: %v", blocked)
	}
}

// ── blockIP — IP inválida (internal) ────────────────────────────────────────

func TestBlockIPInterna_IPInvalida(t *testing.T) {
	e := New(Config{BanSeconds: 3600})

	e.blockIP(context.Background(), detection.Alert{
		IP: "not-valid", Module: "test", Action: detection.ActionBlockIP,
	})

	if e.Stats().BlocksTotal != 0 {
		t.Error("IP inválida en blockIP no debe incrementar BlocksTotal")
	}
}

// ── Run ──────────────────────────────────────────────────────────────────────

func TestRunProcesaNotifyOnly(t *testing.T) {
	n := &captureNotifier{}
	e := New(Config{Notifier: n})

	alertCh := make(chan detection.Alert, 1)
	alertCh <- detection.Alert{
		Module:    "test",
		Action:    detection.ActionNotifyOnly,
		Timestamp: time.Now(),
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		e.Run(ctx, alertCh)
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run no terminó tras cancelar ctx")
	}

	if len(n.alerts) != 1 {
		t.Errorf("Run: esperado 1 alerta procesada, got %d", len(n.alerts))
	}
}

func TestRunSaleConCtxCancelado(t *testing.T) {
	e := New(Config{})
	alertCh := make(chan detection.Alert)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan struct{})
	go func() {
		e.Run(ctx, alertCh)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run no salió con ctx ya cancelado")
	}
}
