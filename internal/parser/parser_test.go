package parser_test

import (
	"testing"
	"time"

	"github.com/perulinux/sendguard/internal/event"
	"github.com/perulinux/sendguard/internal/parser"
)

// ── Tests de ParseLine (mail.log / Postfix) ──────────────────────────────────

func TestParseLine(t *testing.T) {
	p := parser.New()

	tests := []struct {
		name   string
		line   string
		wantOK bool
		wantEv event.Event
	}{
		// --- AuthFailed ---
		{
			name:   "sasl login fallido con IP",
			line:   `May 11 10:23:45 mail postfix/smtpd[1234]: warning: unknown[1.2.3.4]: SASL LOGIN authentication failed: UGFzc3dvcmQ=`,
			wantOK: true,
			wantEv: event.Event{
				Type:    event.AuthFailed,
				Server:  "mail",
				Process: "postfix/smtpd",
				PID:     1234,
				IP:      "1.2.3.4",
			},
		},
		{
			name:   "sasl plain fallido con hostname",
			line:   `May 11 08:00:01 srv01 postfix/smtpd[999]: warning: mail.example.com[203.0.113.5]: SASL PLAIN authentication failed: authentication failure`,
			wantOK: true,
			wantEv: event.Event{
				Type:    event.AuthFailed,
				Server:  "srv01",
				Process: "postfix/smtpd",
				PID:     999,
				IP:      "203.0.113.5",
			},
		},
		{
			name:   "día de mes con espacio (syslog clásico)",
			line:   `May  1 08:00:01 srv01 postfix/smtpd[999]: warning: unknown[10.0.0.1]: SASL LOGIN authentication failed`,
			wantOK: true,
			wantEv: event.Event{
				Type: event.AuthFailed,
				IP:   "10.0.0.1",
			},
		},

		// --- AuthSuccess ---
		{
			name:   "sasl_username con campos adicionales (no capturar coma trailing)",
			line:   `May 11 10:23:45 mail postfix/smtpd[1234]: ABCDEF123456: client=unknown[1.2.3.4], sasl_method=PLAIN, sasl_username=user@domain.com, sasl_sender=`,
			wantOK: true,
			wantEv: event.Event{
				Type:    event.AuthSuccess,
				Account: "user@domain.com",
				IP:      "1.2.3.4",
			},
		},
		{
			name:   "submission puerto 587 (postfix/submission)",
			line:   `May 11 10:23:45 mail postfix/submission[1234]: ABCDEF123456: client=unknown[1.2.3.4], sasl_method=PLAIN, sasl_username=user@domain.com`,
			wantOK: true,
			wantEv: event.Event{
				Type:    event.AuthSuccess,
				Process: "postfix/submission",
				Account: "user@domain.com",
				IP:      "1.2.3.4",
			},
		},
		{
			name:   "submission autenticado con sasl_username",
			line:   `May 11 10:23:45 mail postfix/smtpd[1234]: ABCDEF123456: client=unknown[1.2.3.4], sasl_method=PLAIN, sasl_username=user@domain.com`,
			wantOK: true,
			wantEv: event.Event{
				Type:    event.AuthSuccess,
				Server:  "mail",
				Process: "postfix/smtpd",
				PID:     1234,
				QueueID: "ABCDEF123456",
				IP:      "1.2.3.4",
				Account: "user@domain.com",
				Domain:  "domain.com",
			},
		},
		{
			name:   "conexión sin sasl_username → ignorar",
			line:   `May 11 10:23:45 mail postfix/smtpd[1234]: ABCDEF123456: client=unknown[1.2.3.4]`,
			wantOK: false,
		},

		// --- QueueAccepted ---
		{
			name:   "qmgr acepta mensaje en cola",
			line:   `May 11 10:23:46 mail postfix/qmgr[5678]: ABCDEF123456: from=<user@domain.com>, size=2048, nrcpt=3 (queue active)`,
			wantOK: true,
			wantEv: event.Event{
				Type:    event.QueueAccepted,
				Server:  "mail",
				Process: "postfix/qmgr",
				PID:     5678,
				QueueID: "ABCDEF123456",
				Account: "user@domain.com",
				Domain:  "domain.com",
			},
		},
		{
			// NDR / bounce de Postfix: from=<> no tiene SASL auth previa → ignorar
			// para evitar falsos positivos en number_messages con correo de retorno.
			name:   "qmgr NDR (from vacío) sin auth previa → ignorar",
			line:   `May 11 10:23:46 mail postfix/qmgr[5678]: BCDEF1234567: from=<>, size=512, nrcpt=1 (queue active)`,
			wantOK: false,
		},

		// --- MessageSent / Bounce / Deferred ---
		{
			name:   "entrega exitosa",
			line:   `May 11 10:23:47 mail postfix/smtp[9012]: ABCDEF123456: to=<dest@example.com>, relay=mail.example.com[93.184.216.34]:25, delay=0.5, delays=0.1/0/0.3/0.1, dsn=2.0.0, status=sent (250 2.0.0 OK)`,
			wantOK: true,
			wantEv: event.Event{Type: event.MessageSent, QueueID: "ABCDEF123456"},
		},
		{
			name:   "entrega rebotada",
			line:   `May 11 10:23:47 mail postfix/smtp[9012]: ABCDEF123456: to=<dest@example.com>, relay=mail.example.com[93.184.216.34]:25, delay=2, delays=0.1/0/0.3/1.6, dsn=5.1.1, status=bounced (user unknown)`,
			wantOK: true,
			wantEv: event.Event{Type: event.MessageBounce, QueueID: "ABCDEF123456"},
		},
		{
			name:   "entrega diferida",
			line:   `May 11 10:23:47 mail postfix/smtp[9012]: ABCDEF123456: to=<dest@example.com>, relay=none, delay=10, delays=0.1/0/10/0, dsn=4.4.1, status=deferred (connect to mail.example.com[93.184.216.34]:25: Connection refused)`,
			wantOK: true,
			wantEv: event.Event{Type: event.MessageDeferred, QueueID: "ABCDEF123456"},
		},

		// --- Líneas no relevantes ---
		{
			name:   "línea de cleanup ignorada",
			line:   `May 11 10:23:45 mail postfix/cleanup[1234]: ABCDEF123456: message-id=<abc@domain.com>`,
			wantOK: false,
		},
		{
			name:   "línea vacía ignorada",
			line:   ``,
			wantOK: false,
		},
		{
			name:   "línea con formato ISO 8601",
			line:   `2024-05-11T10:23:45.123+00:00 mail postfix/smtpd[1234]: warning: unknown[5.6.7.8]: SASL LOGIN authentication failed`,
			wantOK: true,
			wantEv: event.Event{
				Type: event.AuthFailed,
				IP:   "5.6.7.8",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ev, ok := p.ParseLine(tc.line)

			if ok != tc.wantOK {
				t.Fatalf("ParseLine() ok=%v, quería %v", ok, tc.wantOK)
			}
			if !tc.wantOK {
				return
			}

			checkEvent(t, ev, tc.wantEv)

			if ev.Raw == "" {
				t.Error("Raw no debe estar vacío")
			}
		})
	}
}

// ── Tests de ParseMailboxLine (mailbox.log / Zimbra) ─────────────────────────

func TestParseMailboxLine(t *testing.T) {
	p := parser.New()

	tests := []struct {
		name   string
		line   string
		wantOK bool
		wantEv event.Event
	}{
		// --- AuthFailed ---
		{
			name:   "imap fallo con cuenta en mensaje",
			line:   `2024-05-11 10:23:45,207 WARN  [ImapServer-1] [ip=1.2.3.4;ua=Thunderbird;] imap - authentication failed for [user@domain.com] (invalid password)`,
			wantOK: true,
			wantEv: event.Event{
				Type:    event.AuthFailed,
				Process: "imap",
				IP:      "1.2.3.4",
				Account: "user@domain.com",
				Domain:  "domain.com",
			},
		},
		{
			name:   "pop3 fallo",
			line:   `2024-05-11 08:00:01,943 WARN  [Pop3Server-3] [ip=5.6.7.8;ua=Outlook;] pop3 - authentication failed for [victim@company.com] (no such account)`,
			wantOK: true,
			wantEv: event.Event{
				Type:    event.AuthFailed,
				Process: "pop3",
				IP:      "5.6.7.8",
				Account: "victim@company.com",
				Domain:  "company.com",
			},
		},
		{
			name:   "soap fallo (webmail)",
			line:   `2024-05-11 09:15:00,001 WARN  [qtp12345-7] [ip=203.0.113.9;ua=ZimbraWebClient;] soap - authentication failed for [admin@domain.com] (invalid credentials)`,
			wantOK: true,
			wantEv: event.Event{
				Type:    event.AuthFailed,
				Process: "soap",
				IP:      "203.0.113.9",
				Account: "admin@domain.com",
			},
		},
		{
			name:   "imap fallo — oip tiene prioridad sobre ip (proxy delante)",
			line:   `2024-05-11 10:23:45,100 WARN  [ImapSSLServer-5] [ip=10.0.0.1;oip=203.0.113.55;ua=Mail;] imap - authentication failed for [user@domain.com] (invalid password)`,
			wantOK: true,
			wantEv: event.Event{
				Type: event.AuthFailed,
				IP:   "203.0.113.55", // oip, no ip (proxy)
			},
		},
		{
			name:   "imap fallo — cuenta en contexto (name=) cuando fallo ocurre tras identificación",
			line:   `2024-05-11 10:23:45,300 WARN  [ImapServer-2] [name=user@domain.com;ip=1.2.3.4;] imap - authentication failed for [user@domain.com] (invalid password)`,
			wantOK: true,
			wantEv: event.Event{
				Type:    event.AuthFailed,
				IP:      "1.2.3.4",
				Account: "user@domain.com",
			},
		},

		// --- AuthSuccess ---
		{
			name:   "imap éxito con mecanismo LOGIN",
			line:   `2024-05-11 10:23:45,207 INFO  [ImapSSLServer-13] [name=user@domain.com;ip=1.2.3.4;oip=5.6.7.8;ua=Thunderbird;] imap - user user@domain.com authenticated, mechanism=LOGIN [TLS]`,
			wantOK: true,
			wantEv: event.Event{
				Type:    event.AuthSuccess,
				Process: "imap",
				IP:      "5.6.7.8", // oip
				Account: "user@domain.com",
				Domain:  "domain.com",
			},
		},
		{
			name:   "pop3 éxito",
			line:   `2024-05-11 11:00:00,500 INFO  [Pop3Server-1] [name=alice@example.com;ip=10.20.30.40;] pop3 - user alice@example.com authenticated`,
			wantOK: true,
			wantEv: event.Event{
				Type:    event.AuthSuccess,
				Process: "pop3",
				IP:      "10.20.30.40",
				Account: "alice@example.com",
				Domain:  "example.com",
			},
		},
		{
			name:   "soap éxito (webmail)",
			line:   `2024-05-11 14:30:00,000 INFO  [qtp99887-3] [name=bob@corp.com;ip=192.168.1.100;oip=8.8.8.8;ua=ZimbraWebClient;] soap - user bob@corp.com authenticated`,
			wantOK: true,
			wantEv: event.Event{
				Type:    event.AuthSuccess,
				Process: "soap",
				IP:      "8.8.8.8",
				Account: "bob@corp.com",
			},
		},

		// --- Líneas ignoradas ---
		{
			name:   "protocolo lmtp → ignorar",
			line:   `2024-05-11 10:23:45,100 INFO  [LmtpServer-1] [ip=127.0.0.1;] lmtp - user user@domain.com authenticated`,
			wantOK: false,
		},
		{
			name:   "protocolo security → ignorar (formato diferente, no implementado)",
			line:   `2024-05-11 10:23:45,100 INFO  [ImapServer-1] [ip=1.2.3.4;] security - cmd=Auth; account=user@domain.com; protocol=imap`,
			wantOK: false,
		},
		{
			name:   "línea de GC/JVM → ignorar",
			line:   `2024-05-11 10:23:45,000 INFO  [GC Daemon] [] system - GC overhead: 5%`,
			wantOK: false,
		},
		{
			name:   "línea vacía → ignorar",
			line:   ``,
			wantOK: false,
		},
		{
			name:   "imap línea sin patrón conocido → ignorar",
			line:   `2024-05-11 10:23:45,100 INFO  [ImapServer-2] [ip=1.2.3.4;] imap - connection dropped`,
			wantOK: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ev, ok := p.ParseMailboxLine(tc.line)

			if ok != tc.wantOK {
				t.Fatalf("ParseMailboxLine() ok=%v, quería %v", ok, tc.wantOK)
			}
			if !tc.wantOK {
				return
			}

			checkEvent(t, ev, tc.wantEv)

			if ev.Raw == "" {
				t.Error("Raw no debe estar vacío")
			}
		})
	}
}

func TestParseMailboxTimestampZone(t *testing.T) {
	p := parser.New()

	// El timestamp de mailbox.log no tiene zona horaria → debe parsearse en zona local.
	line := `2024-05-11 10:23:45,207 INFO  [ImapServer-1] [ip=1.2.3.4;] imap - authentication failed for [user@domain.com] (invalid password)`
	ev, ok := p.ParseMailboxLine(line)
	if !ok {
		t.Fatal("se esperaba parseo exitoso")
	}

	// El año, mes, día y hora deben corresponder al timestamp de la línea.
	if ev.Timestamp.Year() != 2024 {
		t.Errorf("Year: got %d, want 2024", ev.Timestamp.Year())
	}
	if ev.Timestamp.Month() != time.May {
		t.Errorf("Month: got %v, want May", ev.Timestamp.Month())
	}
	if ev.Timestamp.Day() != 11 {
		t.Errorf("Day: got %d, want 11", ev.Timestamp.Day())
	}
	if ev.Timestamp.Hour() != 10 {
		t.Errorf("Hour: got %d, want 10", ev.Timestamp.Hour())
	}
}

// ── Tests de correlación bounce ──────────────────────────────────────────────

// TestBounceCorrelation verifica que un bounce recibe la cuenta del remitente
// autenticado vía SASL, lo que permite que bouncerate detecte cuentas comprometidas.
func TestBounceCorrelation(t *testing.T) {
	p := parser.New()

	// 1. Auth SASL exitosa — registra QUEUEABC en authedQueues
	authLine := `May 11 10:00:00 mail postfix/smtps/smtpd[1]: QUEUEABC: client=unknown[1.2.3.4], sasl_method=PLAIN, sasl_username=spammer@domain.com`
	_, ok := p.ParseLine(authLine)
	if !ok {
		t.Fatal("auth line debe parsear ok")
	}

	// 2. qmgr acepta — mueve QUEUEABC de authedQueues a queueSenders
	qmgrLine := `May 11 10:00:01 mail postfix/qmgr[2]: QUEUEABC: from=<spammer@domain.com>, size=1024, nrcpt=1 (queue active)`
	qmgrEv, ok := p.ParseLine(qmgrLine)
	if !ok {
		t.Fatal("qmgr line debe parsear ok")
	}
	if qmgrEv.Type != event.QueueAccepted {
		t.Fatalf("qmgr: Type got %q, want QueueAccepted", qmgrEv.Type)
	}

	// 3. Entrega rebotada — debe correlacionar Account desde queueSenders
	bounceLine := `May 11 10:00:02 mail postfix/smtp[3]: QUEUEABC: to=<bad@notexist.com>, relay=notexist.com[9.9.9.9]:25, delay=2, delays=0.1/0/0.3/1.6, dsn=5.1.1, status=bounced (user unknown)`
	bounceEv, ok := p.ParseLine(bounceLine)
	if !ok {
		t.Fatal("bounce delivery line debe parsear ok")
	}
	if bounceEv.Type != event.MessageBounce {
		t.Fatalf("bounce: Type got %q, want MessageBounce", bounceEv.Type)
	}
	if bounceEv.Account != "spammer@domain.com" {
		t.Errorf("bounce: Account got %q, want spammer@domain.com (correlación con SASL auth)", bounceEv.Account)
	}
	if bounceEv.Domain != "domain.com" {
		t.Errorf("bounce: Domain got %q, want domain.com", bounceEv.Domain)
	}
}

// TestRecipientAddedCarriesSender verifica que los eventos RecipientAdded llevan
// la cuenta del REMITENTE autenticado (sasl_username), no la del destinatario RCPT TO.
// Regresión: antes ev.Account = m[3] capturaba el email del destinatario, lo que
// causaba que rcptflood intentara suspender una cuenta externa inexistente en Zimbra.
func TestRecipientAddedCarriesSender(t *testing.T) {
	p := parser.New()

	// 1. Auth SASL exitosa — registra QID1 con sasl_username=flood@domain.com
	authLine := `May 11 10:00:00 mail postfix/smtps/smtpd[1]: QID1: client=unknown[198.51.100.1], sasl_method=PLAIN, sasl_username=flood@domain.com`
	authEv, ok := p.ParseLine(authLine)
	if !ok {
		t.Fatal("auth line debe parsear ok")
	}
	if authEv.Account != "flood@domain.com" {
		t.Fatalf("auth: Account got %q, want flood@domain.com", authEv.Account)
	}

	// 2. RCPT filter — el Account del evento debe ser el REMITENTE, no el destinatario
	rcptLine := `May 11 10:00:01 mail postfix/smtps/smtpd[1]: QID1: filter: RCPT from unknown[198.51.100.1]: <victim@external.example>: FILTER smtp-amavis:[127.0.0.1]:10024`
	rcptEv, ok := p.ParseLine(rcptLine)
	if !ok {
		t.Fatal("rcpt filter line debe parsear ok")
	}
	if rcptEv.Type != event.RecipientAdded {
		t.Fatalf("Type: got %q, want RecipientAdded", rcptEv.Type)
	}
	if rcptEv.Account != "flood@domain.com" {
		t.Errorf("Account: got %q, want flood@domain.com (remitente SASL, no destinatario RCPT)", rcptEv.Account)
	}
	if rcptEv.Domain != "domain.com" {
		t.Errorf("Domain: got %q, want domain.com", rcptEv.Domain)
	}
	if rcptEv.IP != "198.51.100.1" {
		t.Errorf("IP: got %q, want 198.51.100.1", rcptEv.IP)
	}
}

// TestBounceWithoutAuth verifica que un bounce de correo no autenticado (entrante MX)
// no recibe Account — sin correlación no hay false positives en bouncerate.
func TestBounceWithoutAuth(t *testing.T) {
	p := parser.New()

	// Bounce de correo entrante: no hay SASL auth, QUEUEMX no está en queueSenders
	bounceLine := `May 11 10:00:05 mail postfix/smtp[9]: QUEUEMX1: to=<user@domain.com>, relay=domain.com[1.2.3.4]:25, delay=1, delays=0.1/0/0.3/0.6, dsn=5.1.1, status=bounced (user unknown)`
	ev, ok := p.ParseLine(bounceLine)
	if !ok {
		t.Fatal("bounce line debe parsear ok (siempre emitimos MessageBounce/Sent/Deferred)")
	}
	if ev.Type != event.MessageBounce {
		t.Fatalf("Type got %q, want MessageBounce", ev.Type)
	}
	if ev.Account != "" {
		t.Errorf("Account got %q, want \"\" (correo sin auth no debe tener remitente correlacionado)", ev.Account)
	}
}

// ── Helper compartido ────────────────────────────────────────────────────────

// checkEvent verifica solo los campos no-cero del evento esperado.
func checkEvent(t *testing.T, got, want event.Event) {
	t.Helper()
	if want.Type != "" && got.Type != want.Type {
		t.Errorf("Type: got %q, want %q", got.Type, want.Type)
	}
	if want.Server != "" && got.Server != want.Server {
		t.Errorf("Server: got %q, want %q", got.Server, want.Server)
	}
	if want.Process != "" && got.Process != want.Process {
		t.Errorf("Process: got %q, want %q", got.Process, want.Process)
	}
	if want.PID != 0 && got.PID != want.PID {
		t.Errorf("PID: got %d, want %d", got.PID, want.PID)
	}
	if want.IP != "" && got.IP != want.IP {
		t.Errorf("IP: got %q, want %q", got.IP, want.IP)
	}
	if want.Account != "" && got.Account != want.Account {
		t.Errorf("Account: got %q, want %q", got.Account, want.Account)
	}
	if want.Domain != "" && got.Domain != want.Domain {
		t.Errorf("Domain: got %q, want %q", got.Domain, want.Domain)
	}
	if want.QueueID != "" && got.QueueID != want.QueueID {
		t.Errorf("QueueID: got %q, want %q", got.QueueID, want.QueueID)
	}
}
