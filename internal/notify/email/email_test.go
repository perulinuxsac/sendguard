package email

import (
	"context"
	"mime"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/perulinux/sendguard/internal/detection"
	"github.com/perulinux/sendguard/internal/notify/present"
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

// El asunto va codificado (RFC 2047) y, decodificado, dice el resultado real.
func TestSubjectCodificadoYLegible(t *testing.T) {
	n := New(Config{From: "sg@dominio.com", To: []string{"noc@dominio.com"}})
	a := sampleAlert()
	a.Outcome = detection.OutcomeApplied
	msg := n.buildMessage(a)
	var raw string
	for _, l := range strings.Split(msg, "\r\n") {
		if strings.HasPrefix(l, "Subject: ") {
			raw = strings.TrimPrefix(l, "Subject: ")
		}
	}
	if !strings.HasPrefix(raw, "=?utf-8?q?") {
		t.Fatalf("el asunto debe ir codificado RFC 2047: %q", raw)
	}
	subj, err := new(mime.WordDecoder).DecodeHeader(raw)
	if err != nil {
		t.Fatal(err)
	}
	want := "[SendGuard] 🔒 Cuenta suspendida: victim@dominio.com (mail01)"
	if subj != want {
		t.Errorf("asunto: got %q, want %q", subj, want)
	}
}

// (a)/(b): una suspensión fallida NO puede verse como "Cuenta suspendida".
func TestSuspensionFallidaSeVeComoFallo(t *testing.T) {
	a := sampleAlert()
	a.Outcome = detection.OutcomeFailed
	a.OutcomeDetail = "FALLÓ la suspensión — la cuenta sigue activa. zmprov: account not found"
	a.Effects = []detection.Effect{{Outcome: detection.OutcomeFailed, Text: a.OutcomeDetail}}

	for name, body := range map[string]string{
		"plain": buildPlain(a, a.Timestamp),
		"html":  buildHTML(a, a.Timestamp),
	} {
		if !strings.Contains(body, "FALLÓ la suspensión de la cuenta") || !strings.Contains(body, "sigue ACTIVA") {
			t.Errorf("%s: debe decir que la suspensión falló y la cuenta sigue activa", name)
		}
		if strings.Contains(body, "Cuenta suspendida") {
			t.Errorf("%s: no debe decir 'Cuenta suspendida' si falló", name)
		}
		if strings.Contains(body, "sendguard-ctl unsuspend") {
			t.Errorf("%s: no hay nada que revertir si la suspensión falló", name)
		}
	}
}

// Suspensión aplicada: muestra las acciones del agente y cómo revertir.
func TestSuspensionAplicadaMuestraAccionesYRevertir(t *testing.T) {
	a := sampleAlert()
	a.Outcome = detection.OutcomeApplied
	a.Country = "cn"
	a.Effects = []detection.Effect{
		{Outcome: detection.OutcomeApplied, Text: "Cuenta bloqueada en Zimbra (zimbraAccountStatus=locked)"},
		{Outcome: detection.OutcomeApplied, Text: "IP 203.0.113.7 bloqueada en el firewall por 1 h"},
	}
	for name, body := range map[string]string{
		"plain": buildPlain(a, a.Timestamp),
		"html":  buildHTML(a, a.Timestamp),
	} {
		for _, want := range []string{"Cuenta suspendida", "Cuenta bloqueada en Zimbra",
			"bloqueada en el firewall por 1 h", "sendguard-ctl unsuspend victim@dominio.com", "🇨🇳 CN"} {
			if !strings.Contains(body, want) {
				t.Errorf("%s: falta %q", name, want)
			}
		}
	}
}

// Omitida por país permitido: título de revisión, no de suspensión.
func TestSuspensionOmitidaPideRevision(t *testing.T) {
	a := sampleAlert()
	a.Outcome = detection.OutcomeSkipped
	a.Effects = []detection.Effect{{Outcome: detection.OutcomeSkipped, Text: "Suspensión omitida: país permitido (PE)"}}
	body := buildHTML(a, a.Timestamp)
	if !strings.Contains(body, "Suspensión omitida — revisar") || !strings.Contains(body, "país permitido") {
		t.Error("una suspensión omitida debe titularse como revisión")
	}
}

func TestTonePaletteCompleta(t *testing.T) {
	for _, tone := range []present.Tone{present.ToneInfo, present.ToneMuted, present.ToneWarning,
		present.ToneHigh, present.ToneCritical, present.ToneFailed} {
		p := tonePalette(tone)
		if p.accent == "" || p.soft == "" || p.ink == "" {
			t.Errorf("tono %d: color vacío %+v", tone, p)
		}
	}
}

func TestNotifySendmailColgadoRespetaTimeout(t *testing.T) {
	// Un sendmail que nunca termina no debe congelar Notify (que corre en el
	// goroutine del enforcer): el timeout local debe matarlo.
	dir := t.TempDir()
	bin := filepath.Join(dir, "sendmail")
	// El sleep largo simula postdrop trabado; el timeout de test lo corta.
	os.WriteFile(bin, []byte("#!/bin/sh\nsleep 30\n"), 0755)

	old := sendmailTimeout
	sendmailTimeout = 200 * time.Millisecond
	defer func() { sendmailTimeout = old }()

	n := New(Config{From: "sg@d.com", To: []string{"noc@d.com"}, SendmailBin: bin})

	done := make(chan error, 1)
	go func() { done <- n.Notify(context.Background(), sampleAlert()) }()

	select {
	case err := <-done:
		if err == nil {
			t.Error("sendmail colgado debe retornar error por timeout")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Notify quedó colgado pese al timeout")
	}
}

func TestNotifySuspendedUserSendmailColgadoRespetaTimeout(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "sendmail")
	os.WriteFile(bin, []byte("#!/bin/sh\nsleep 30\n"), 0755)

	old := sendmailTimeout
	sendmailTimeout = 200 * time.Millisecond
	defer func() { sendmailTimeout = old }()

	n := New(Config{From: "sg@d.com", SendmailBin: bin})

	done := make(chan error, 1)
	go func() { done <- n.NotifySuspendedUser(context.Background(), "user@d.com", sampleAlert()) }()

	select {
	case err := <-done:
		if err == nil {
			t.Error("sendmail colgado debe retornar error por timeout")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("NotifySuspendedUser quedó colgado pese al timeout")
	}
}
