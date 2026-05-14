// Package parser extrae eventos de seguridad de las líneas de log de Zimbra/Postfix.
// Soporta dos fuentes:
//   - /var/log/mail.log       → ParseLine()        (Postfix/SMTP, syslog clásico o ISO 8601)
//   - /opt/zimbra/log/mailbox.log → ParseMailboxLine() (Zimbra IMAP/POP3/SOAP, formato propio)
package parser

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/perulinux/sendguard/internal/event"
)

// ── Regexes para /var/log/mail.log ──────────────────────────────────────────

// reHeader parsea la cabecera estándar syslog:
//
//	"May 11 10:23:45 hostname postfix/smtpd[1234]: mensaje"
//	"May  1 10:23:45 hostname postfix/smtpd[1234]: mensaje"  (día con espacio)
//
// También acepta ISO 8601 (rsyslog moderno):
//
//	"2024-05-11T10:23:45.123+00:00 hostname postfix/smtpd[1234]: mensaje"
var reHeader = regexp.MustCompile(
	`^` +
		`(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}` + // syslog clásico: "May 11 10:23:45"
		`|\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2}|Z)?)` + // ISO 8601
		`\s+(\S+)` + // hostname
		`\s+(\S+?)\[(\d+)\]:\s+` + // proceso[pid]:
		`(.+)$`, // mensaje
)

var (
	// warning: unknown[1.2.3.4]: SASL LOGIN authentication failed: motivo
	reSaslFail = regexp.MustCompile(
		`^warning:\s+\S+\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]:\s+SASL\s+\S+\s+authentication\s+failed(?::\s+(.+))?$`,
	)

	// ABCDEF1234: client=hostname[1.2.3.4], sasl_method=PLAIN, sasl_username=user@domain.com
	// [^\s,]+ evita capturar la coma trailing cuando hay más campos después de sasl_username.
	reSaslSuccess = regexp.MustCompile(
		`^(\w+):\s+client=\S+\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\].*?sasl_username=([^\s,]+)`,
	)

	// ABCDEF1234: from=<user@domain.com>, size=1234, nrcpt=2 (queue active)
	reQmgrFrom = regexp.MustCompile(
		`^(\w+):\s+from=<([^>]*)>,\s+size=(\d+),\s+nrcpt=(\d+)`,
	)

	// ABCDEF1234: to=<dest@domain>, relay=..., ..., status=sent|bounced|deferred (...)
	reDelivery = regexp.MustCompile(
		`^(\w+):\s+to=<([^>]*)>,\s+relay=(\S+),.*?\bstatus=(sent|bounced|deferred)\b`,
	)
)

// ── Regexes para /opt/zimbra/log/mailbox.log ────────────────────────────────

// reMailboxHeader parsea la cabecera de mailbox.log:
//
//	"2024-05-11 10:23:45,207 INFO  [ImapSSLServer-13] [name=user@domain;ip=1.2.3.4;oip=5.6.7.8;] imap - mensaje"
//
// Grupos: (1) timestamp  (2) contexto clave=valor  (3) protocolo  (4) mensaje
var reMailboxHeader = regexp.MustCompile(
	`^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d+)` + // timestamp con milisegundos
		`\s+(?:INFO|WARN|ERROR|DEBUG|FATAL)\s+` + // nivel de log
		`\[[^\]]+\]\s+` + // thread (ignorado)
		`\[([^\]]*)\]\s+` + // contexto: "name=...;ip=...;oip=...;"
		`(\w+)\s+-\s+` + // protocolo: "imap", "pop3", "soap", "security"
		`(.+)$`, // mensaje
)

var (
	// "authentication failed for [user@domain.com] (invalid password)"
	reMailboxFail = regexp.MustCompile(
		`^authentication failed for \[([^\]]+)\]`,
	)

	// "user user@domain.com authenticated, mechanism=LOGIN [TLS]"
	reMailboxSuccess = regexp.MustCompile(
		`^user\s+(\S+@\S+)\s+authenticated`,
	)
)

// ── Parser ───────────────────────────────────────────────────────────────────

// Parser convierte líneas de log en eventos tipados.
type Parser struct{}

// New crea un Parser listo para usar.
func New() *Parser { return &Parser{} }

// ParseLine extrae un evento de una línea de /var/log/mail.log (Postfix/syslog).
// Retorna (event, true) si la línea produce un evento relevante.
func (p *Parser) ParseLine(line string) (event.Event, bool) {
	m := reHeader.FindStringSubmatch(line)
	if m == nil {
		return event.Event{}, false
	}

	rawTS, hostname, process, rawPID, msg := m[1], m[2], m[3], m[4], m[5]

	ts := parseTimestamp(rawTS)
	pid, _ := strconv.Atoi(rawPID)

	ev := event.Event{
		Timestamp: ts,
		Server:    hostname,
		Process:   process,
		PID:       pid,
		Raw:       line,
	}

	switch {
	case strings.HasSuffix(process, "/smtpd"),
		strings.HasSuffix(process, "/submission"):
		return p.parseSmtpd(ev, msg)
	case strings.HasSuffix(process, "/qmgr"):
		return p.parseQmgr(ev, msg)
	case strings.HasSuffix(process, "/smtp"),
		strings.HasSuffix(process, "/lmtp"):
		return p.parseDelivery(ev, msg)
	}

	return event.Event{}, false
}

// ParseMailboxLine extrae un evento de una línea de /opt/zimbra/log/mailbox.log.
// Detecta autenticaciones IMAP, POP3 y SOAP (webmail), tanto exitosas como fallidas.
// Retorna (event, true) si la línea produce un evento relevante.
func (p *Parser) ParseMailboxLine(line string) (event.Event, bool) {
	m := reMailboxHeader.FindStringSubmatch(line)
	if m == nil {
		return event.Event{}, false
	}

	rawTS, rawCtx, protocol, msg := m[1], m[2], m[3], m[4]

	ctx := parseMailboxContext(rawCtx)
	ip := mailboxIP(ctx)
	account := ctx["name"]

	ev := event.Event{
		Timestamp: parseMailboxTimestamp(rawTS),
		Process:   protocol,
		IP:        ip,
		Account:   account,
		Domain:    extractDomain(account),
		Raw:       line,
	}

	// Protocolos de interés: IMAP, POP3, SOAP (webmail/ActiveSync).
	switch strings.ToLower(protocol) {
	case "imap", "pop3", "soap":
		return p.parseMailboxProtocol(ev, msg)
	}

	return event.Event{}, false
}

// parseMailboxProtocol aplica los patrones de auth sobre el mensaje del protocolo.
func (p *Parser) parseMailboxProtocol(ev event.Event, msg string) (event.Event, bool) {
	if m := reMailboxFail.FindStringSubmatch(msg); m != nil {
		ev.Type = event.AuthFailed
		// Si el contexto no tenía name= (fallo antes de identificar al usuario),
		// lo extraemos del mensaje: "authentication failed for [user@domain.com]"
		if ev.Account == "" {
			ev.Account = m[1]
			ev.Domain = extractDomain(m[1])
		}
		return ev, true
	}

	if m := reMailboxSuccess.FindStringSubmatch(msg); m != nil {
		ev.Type = event.AuthSuccess
		// El mensaje tiene la cuenta autoritativa ("user X authenticated").
		ev.Account = m[1]
		ev.Domain = extractDomain(m[1])
		return ev, true
	}

	return event.Event{}, false
}

// ── Helpers de mail.log ──────────────────────────────────────────────────────

func (p *Parser) parseSmtpd(ev event.Event, msg string) (event.Event, bool) {
	if m := reSaslFail.FindStringSubmatch(msg); m != nil {
		ev.Type = event.AuthFailed
		ev.IP = m[1]
		if m[2] != "" {
			ev.Extra = map[string]string{"reason": m[2]}
		}
		return ev, true
	}

	if m := reSaslSuccess.FindStringSubmatch(msg); m != nil {
		ev.Type = event.AuthSuccess
		ev.QueueID = m[1]
		ev.IP = m[2]
		ev.Account = m[3]
		ev.Domain = extractDomain(m[3])
		return ev, true
	}

	return event.Event{}, false
}

func (p *Parser) parseQmgr(ev event.Event, msg string) (event.Event, bool) {
	m := reQmgrFrom.FindStringSubmatch(msg)
	if m == nil {
		return event.Event{}, false
	}

	ev.Type = event.QueueAccepted
	ev.QueueID = m[1]
	ev.Account = m[2]
	ev.Domain = extractDomain(m[2])
	ev.Extra = map[string]string{
		"size":  m[3],
		"nrcpt": m[4],
	}
	return ev, true
}

func (p *Parser) parseDelivery(ev event.Event, msg string) (event.Event, bool) {
	m := reDelivery.FindStringSubmatch(msg)
	if m == nil {
		return event.Event{}, false
	}

	ev.QueueID = m[1]
	ev.Extra = map[string]string{
		"to":    m[2],
		"relay": m[3],
	}

	switch m[4] {
	case "sent":
		ev.Type = event.MessageSent
	case "bounced":
		ev.Type = event.MessageBounce
	case "deferred":
		ev.Type = event.MessageDeferred
	default:
		return event.Event{}, false
	}

	return ev, true
}

// ── Helpers de mailbox.log ───────────────────────────────────────────────────

// parseMailboxContext convierte el bloque de contexto en un mapa clave→valor.
// Formato: "name=user@domain.com;ip=1.2.3.4;oip=5.6.7.8;ua=Thunderbird;"
// También acepta espacios después del punto y coma: "ip=1.2.3.4; ua=Mail;"
func parseMailboxContext(ctx string) map[string]string {
	result := make(map[string]string)
	for _, part := range strings.Split(ctx, ";") {
		part = strings.TrimSpace(part)
		idx := strings.IndexByte(part, '=')
		if idx <= 0 {
			continue
		}
		key := strings.TrimSpace(part[:idx])
		val := strings.TrimSpace(part[idx+1:])
		if key != "" && val != "" {
			result[key] = val
		}
	}
	return result
}

// mailboxIP devuelve la IP del cliente real.
// Cuando Zimbra Proxy está delante, "ip" es la del proxy y "oip" es la del cliente real.
func mailboxIP(ctx map[string]string) string {
	if oip := ctx["oip"]; oip != "" {
		return oip
	}
	return ctx["ip"]
}

// parseMailboxTimestamp parsea el formato de timestamp de mailbox.log:
// "2024-05-11 10:23:45,207" (coma separa segundos de milisegundos, zona local).
func parseMailboxTimestamp(s string) time.Time {
	// Reemplazar coma por punto para usar los layouts estándar de Go.
	s = strings.Replace(s, ",", ".", 1)
	if t, err := time.ParseInLocation("2006-01-02 15:04:05.000", s, time.Local); err == nil {
		return t
	}
	// Fallback sin milisegundos (en caso de log truncado).
	if len(s) >= 19 {
		if t, err := time.ParseInLocation("2006-01-02 15:04:05", s[:19], time.Local); err == nil {
			return t
		}
	}
	return time.Now()
}

// ── Helpers compartidos ──────────────────────────────────────────────────────

// parseTimestamp soporta los formatos de /var/log/mail.log:
//
//	Syslog clásico: "May 11 10:23:45"  (sin año → se asume el año actual)
//	ISO 8601:       "2024-05-11T10:23:45.123+00:00"
func parseTimestamp(s string) time.Time {
	for _, layout := range []string{
		"2006-01-02T15:04:05.999999999Z07:00",
		"2006-01-02T15:04:05Z07:00",
		"2006-01-02 15:04:05",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}

	t, err := time.Parse("Jan _2 15:04:05", s)
	if err != nil {
		return time.Now()
	}

	now := time.Now()
	t = time.Date(now.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), 0, now.Location())
	if t.After(now.Add(24 * time.Hour)) {
		t = t.AddDate(-1, 0, 0)
	}
	return t
}

// extractDomain extrae el dominio de "user@domain.com". Si no hay @, retorna "".
func extractDomain(account string) string {
	if i := strings.LastIndex(account, "@"); i >= 0 {
		return account[i+1:]
	}
	return ""
}
