package report

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/perulinux/sendguard/internal/detection"
	"github.com/perulinux/sendguard/internal/enforcement"
)

type fakeEnforcer struct {
	blocked   []enforcement.BlockedIPInfo
	suspended []enforcement.SuspendedAcctInfo
	stats     enforcement.EnforcerStats
}

func (f fakeEnforcer) BlockedIPs() []enforcement.BlockedIPInfo            { return f.blocked }
func (f fakeEnforcer) SuspendedAccounts() []enforcement.SuspendedAcctInfo { return f.suspended }
func (f fakeEnforcer) Stats() enforcement.EnforcerStats                   { return f.stats }

type fakeEngine struct {
	events int64
	alerts int64
	mods   []detection.ModuleStat
}

func (f fakeEngine) EventsTotal() int64                  { return f.events }
func (f fakeEngine) AlertsTotal() int64                  { return f.alerts }
func (f fakeEngine) ModuleStats() []detection.ModuleStat { return f.mods }

func sampleViews() (fakeEnforcer, fakeEngine) {
	now := time.Now()
	enf := fakeEnforcer{
		blocked: []enforcement.BlockedIPInfo{
			{IP: "203.0.113.1", Module: "auth_failed", Expiry: now.Add(time.Hour)},
			{IP: "203.0.113.2", Module: "password_spray", Expiry: now.Add(200 * 365 * 24 * time.Hour)}, // permanente
		},
		suspended: []enforcement.SuspendedAcctInfo{
			{Account: "victim@dominio.com", Module: "rcpt_flood", Timestamp: now},
		},
		stats: enforcement.EnforcerStats{BlocksTotal: 12, SuspensionsTotal: 3, RateLimitsTotal: 1},
	}
	eng := fakeEngine{
		events: 5000,
		alerts: 42,
		mods: []detection.ModuleStat{
			{Module: "auth_failed", Alerts: 20},
			{Module: "rcpt_flood", Alerts: 22},
		},
	}
	return enf, eng
}

func TestNewDefaults(t *testing.T) {
	r := New(Config{}, fakeEnforcer{}, fakeEngine{})
	if r.cfg.SendmailBin != defaultSendmail {
		t.Errorf("SendmailBin por defecto: got %q", r.cfg.SendmailBin)
	}
	// Hour=0 es medianoche (válido); New solo normaliza valores fuera de rango.
	if r.cfg.Hour != 0 {
		t.Errorf("Hour=0 debe respetarse (medianoche), got %d", r.cfg.Hour)
	}
	// Hora fuera de rango se normaliza a 8.
	for _, h := range []int{-1, 24, 99} {
		if got := New(Config{Hour: h}, fakeEnforcer{}, fakeEngine{}).cfg.Hour; got != 8 {
			t.Errorf("Hour=%d debe normalizarse a 8, got %d", h, got)
		}
	}
	// Hora válida se respeta.
	if got := New(Config{Hour: 14}, fakeEnforcer{}, fakeEngine{}).cfg.Hour; got != 14 {
		t.Errorf("Hour=14 debe respetarse, got %d", got)
	}
}

func TestNextScheduled(t *testing.T) {
	// Antes de la hora: mismo día.
	now := time.Date(2026, 5, 29, 6, 0, 0, 0, time.UTC)
	next := nextScheduled(now, 8)
	want := time.Date(2026, 5, 29, 8, 0, 0, 0, time.UTC)
	if !next.Equal(want) {
		t.Errorf("antes de la hora: got %v, want %v", next, want)
	}

	// Exactamente a la hora o después: día siguiente.
	now2 := time.Date(2026, 5, 29, 8, 0, 0, 0, time.UTC)
	next2 := nextScheduled(now2, 8)
	want2 := time.Date(2026, 5, 30, 8, 0, 0, 0, time.UTC)
	if !next2.Equal(want2) {
		t.Errorf("a la hora exacta: got %v, want %v", next2, want2)
	}

	now3 := time.Date(2026, 5, 29, 20, 0, 0, 0, time.UTC)
	next3 := nextScheduled(now3, 8)
	if !next3.After(now3) || next3.Day() != 30 {
		t.Errorf("después de la hora: got %v", next3)
	}
}

func TestSendNoopWhenUnconfigured(t *testing.T) {
	enf, eng := sampleViews()
	cases := []Config{
		{},                                     // sin From ni To
		{EmailFrom: "sg@dominio.com"},          // sin To
		{EmailTo: []string{"noc@dominio.com"}}, // sin From
	}
	for i, c := range cases {
		r := New(c, enf, eng)
		if err := r.Send(context.Background()); err != nil {
			t.Errorf("caso %d: Send debe ser no-op (nil), got %v", i, err)
		}
	}
}

func TestBuildMessageStructure(t *testing.T) {
	enf, eng := sampleViews()
	r := New(Config{
		EmailFrom: "sg@dominio.com", EmailTo: []string{"noc@dominio.com"},
		ServerID: "cliente-mail1", ClientName: "Cliente ABC",
	}, enf, eng)

	msg := r.buildMessage()
	for _, w := range []string{
		"From: SendGuard <sg@dominio.com>",
		"To: noc@dominio.com",
		"Resumen diario",
		"cliente-mail1",
		"multipart/alternative",
		mimeBoundary,
		"--" + mimeBoundary + "--",
	} {
		if !strings.Contains(msg, w) {
			t.Errorf("buildMessage no contiene %q", w)
		}
	}
}

func TestBuildPlainContent(t *testing.T) {
	enf, eng := sampleViews()
	r := New(Config{ServerID: "cliente-mail1"}, enf, eng)
	plain := r.buildPlain(time.Now().UTC(), enf.stats, enf.blocked, enf.suspended, eng.mods)

	for _, w := range []string{
		"cliente-mail1", "203.0.113.1", "victim@dominio.com",
		"auth_failed", "rcpt_flood", "5000", "42",
	} {
		if !strings.Contains(plain, w) {
			t.Errorf("buildPlain no contiene %q", w)
		}
	}
}

func TestBuildHTMLContentAndEscaping(t *testing.T) {
	enf, eng := sampleViews()
	enf.suspended[0].Account = "<b>x</b>@dominio.com"
	r := New(Config{ServerID: "cliente-mail1", ClientName: "Cliente ABC"}, enf, eng)
	htmlMsg := r.buildHTML(time.Now().UTC(), enf.stats, enf.blocked, enf.suspended, eng.mods)

	if strings.Contains(htmlMsg, "<b>x</b>@dominio.com") {
		t.Error("buildHTML no escapó la cuenta suspendida")
	}
	if !strings.Contains(htmlMsg, "Cliente ABC") {
		t.Error("buildHTML debe incluir el nombre del cliente")
	}
	if !strings.Contains(htmlMsg, "permanente") {
		t.Error("buildHTML debe mostrar TTL 'permanente' para bans sin expiración")
	}
}

func TestBuildHTMLNoActivity(t *testing.T) {
	r := New(Config{ServerID: "cliente-mail1"}, fakeEnforcer{}, fakeEngine{})
	htmlMsg := r.buildHTML(time.Now().UTC(), enforcement.EnforcerStats{}, nil, nil, nil)
	if !strings.Contains(htmlMsg, "Sin actividad") {
		t.Error("buildHTML debe mostrar el bloque 'Sin actividad' cuando no hay datos")
	}
}

func TestBuildHTMLManyBlockedTruncates(t *testing.T) {
	now := time.Now()
	var blocked []enforcement.BlockedIPInfo
	for i := 0; i < 20; i++ {
		blocked = append(blocked, enforcement.BlockedIPInfo{
			IP: "203.0.113." + string(rune('0'+i%10)), Module: "auth_failed", Expiry: now.Add(time.Hour),
		})
	}
	r := New(Config{ServerID: "x"}, fakeEnforcer{blocked: blocked}, fakeEngine{})
	htmlMsg := r.buildHTML(now.UTC(), enforcement.EnforcerStats{}, blocked, nil, nil)
	if !strings.Contains(htmlMsg, "y 5 más") {
		t.Error("buildHTML debe truncar a 15 IPs y mostrar '… y N más'")
	}
}
