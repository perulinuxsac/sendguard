package email

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/perulinux/sendguard/internal/detection"
)

func sampleAlert() detection.Alert {
	return detection.Alert{
		Module:    "rcpt_flood",
		Score:     90,
		Severity:  detection.SeveritySuspend,
		Action:    detection.ActionSuspendAcct,
		Timestamp: time.Date(2026, 5, 29, 10, 30, 0, 0, time.UTC),
		Server:    "mail01",
		IP:        "203.0.113.7",
		Account:   "victim@dominio.com",
		Domain:    "dominio.com",
		Reasons:   []string{"50 destinatarios en 5m0s", "AbuseIPDB score: 90/100"},
	}
}

func TestNewDefaultsSendmail(t *testing.T) {
	n := New(Config{From: "a@b.com", To: []string{"c@d.com"}})
	if n.cfg.SendmailBin != defaultSendmail {
		t.Errorf("SendmailBin por defecto: got %q, want %q", n.cfg.SendmailBin, defaultSendmail)
	}
	n2 := New(Config{SendmailBin: "/custom/sendmail"})
	if n2.cfg.SendmailBin != "/custom/sendmail" {
		t.Errorf("SendmailBin custom no respetado: %q", n2.cfg.SendmailBin)
	}
}

func TestNotifyNoopWhenUnconfigured(t *testing.T) {
	// Sin To ni From, Notify no debe ejecutar sendmail y retornar nil.
	cases := []Config{
		{},
		{From: "a@b.com"},         // sin To
		{To: []string{"c@d.com"}}, // sin From
	}
	for i, c := range cases {
		n := New(c)
		if err := n.Notify(context.Background(), sampleAlert()); err != nil {
			t.Errorf("caso %d: Notify debe ser no-op (nil), got %v", i, err)
		}
	}
}

func TestBuildMessageStructure(t *testing.T) {
	n := New(Config{From: "sg@dominio.com", To: []string{"noc@dominio.com", "admin@dominio.com"}})
	msg := n.buildMessage(sampleAlert())

	wantContains := []string{
		"From: SendGuard <sg@dominio.com>",
		"To: noc@dominio.com, admin@dominio.com",
		"MIME-Version: 1.0",
		"multipart/alternative",
		mimeBoundary,
		"Content-Type: text/plain; charset=utf-8",
		"Content-Type: text/html; charset=utf-8",
		"--" + mimeBoundary + "--", // cierre
	}
	for _, w := range wantContains {
		if !strings.Contains(msg, w) {
			t.Errorf("buildMessage no contiene %q", w)
		}
	}
}

func TestBuildPlainContainsFields(t *testing.T) {
	a := sampleAlert()
	plain := buildPlain(a, a.Timestamp)
	for _, w := range []string{"victim@dominio.com", "203.0.113.7", "mail01", "dominio.com",
		"50 destinatarios en 5m0s", "CRÍTICO"} {
		if !strings.Contains(plain, w) {
			t.Errorf("buildPlain no contiene %q", w)
		}
	}
}

func TestBuildPlainOmitsEmptyFields(t *testing.T) {
	a := detection.Alert{
		Module:    "auth_failed",
		Action:    detection.ActionBlockIP,
		Severity:  detection.SeverityWarn,
		Timestamp: time.Now(),
		IP:        "203.0.113.1",
		// Sin Account, Server, Domain
	}
	plain := buildPlain(a, a.Timestamp)
	if strings.Contains(plain, "Cuenta") {
		t.Error("buildPlain no debe incluir la línea Cuenta cuando está vacía")
	}
	if strings.Contains(plain, "Servidor") {
		t.Error("buildPlain no debe incluir la línea Servidor cuando está vacía")
	}
}

func TestBuildHTMLEscapesAndContains(t *testing.T) {
	a := sampleAlert()
	a.Account = "<script>@evil.com"
	htmlMsg := buildHTML(a, a.Timestamp)
	if strings.Contains(htmlMsg, "<script>@evil.com") {
		t.Error("buildHTML no escapó el contenido del Account")
	}
	if !strings.Contains(htmlMsg, "&lt;script&gt;") {
		t.Error("buildHTML debe contener la versión escapada del Account")
	}
	if !strings.Contains(htmlMsg, "SendGuard") {
		t.Error("buildHTML debe contener la marca SendGuard")
	}
}

func TestFormatSubjectFallback(t *testing.T) {
	// Con IP presente usa la IP como target.
	a := sampleAlert()
	subj := formatSubject(a)
	if !strings.Contains(subj, "203.0.113.7") || !strings.Contains(subj, "mail01") {
		t.Errorf("subject inesperado: %q", subj)
	}

	// Sin IP ni cuenta ni dominio, cae al módulo; sin server usa "sendguard".
	a2 := detection.Alert{Module: "queue_monitor", Action: detection.ActionNotifyOnly, Severity: detection.SeverityWarn}
	subj2 := formatSubject(a2)
	if !strings.Contains(subj2, "queue_monitor") || !strings.Contains(subj2, "sendguard") {
		t.Errorf("subject fallback inesperado: %q", subj2)
	}
}

func TestSeverityLabels(t *testing.T) {
	cases := map[detection.Severity]string{
		detection.SeveritySuspend:   "CRÍTICO",
		detection.SeverityRateLimit: "ALTO",
		detection.SeverityWarn:      "MEDIO",
		detection.SeverityLog:       "INFO",
	}
	for sev, want := range cases {
		if got := severityLabel(sev); got != want {
			t.Errorf("severityLabel(%d): got %q, want %q", sev, got, want)
		}
		// Color/bg/header no deben estar vacíos para ninguna severidad.
		if severityColor(sev) == "" || severityBg(sev) == "" || headerColor(sev) == "" {
			t.Errorf("severidad %d: algún color vacío", sev)
		}
	}
}

func TestActionLabelAndIcon(t *testing.T) {
	actions := []detection.Action{
		detection.ActionBlockIP, detection.ActionSuspendAcct, detection.ActionUnsuspendAcct,
		detection.ActionRateLimit, detection.ActionNotifyOnly, detection.ActionPurgeQueue,
	}
	for _, a := range actions {
		if actionLabel(a, "") == "" {
			t.Errorf("actionLabel(%q) vacío", a)
		}
		if actionIcon(a, "") == "" {
			t.Errorf("actionIcon(%q) vacío", a)
		}
	}

	// notify_only usa el módulo para dar contexto.
	mods := []string{"queue_monitor", "dist_brute_force", "domain_discovery",
		"bounce_rate", "account_takeover", "otro"}
	for _, m := range mods {
		if actionLabel(detection.ActionNotifyOnly, m) == "" {
			t.Errorf("actionLabel(notify_only, %q) vacío", m)
		}
		if actionIcon(detection.ActionNotifyOnly, m) == "" {
			t.Errorf("actionIcon(notify_only, %q) vacío", m)
		}
	}
}
