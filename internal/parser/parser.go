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

	// ABCDEF1234: filter: RCPT from unknown[1.2.3.4]: <sender@domain>: ...
	// Captura cada destinatario añadido en una sesión autenticada (spam masivo, content filter).
	reRcptFilter = regexp.MustCompile(
		`^(\w+): filter: RCPT from \S+\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]: <([^>]+)>:`,
	)

	// ABCDEF1234: from=<user@domain.com>, size=1234, nrcpt=2 (queue active)
	// \s* en vez de \s+ porque algunos transportes omiten el espacio tras la coma.
	reQmgrFrom = regexp.MustCompile(
		`^(\w+):\s+from=<([^>]*)>,\s*size=(\d+),\s*nrcpt=(\d+)`,
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
	// "authentication failed for [user@domain.com] (invalid password)"  — IMAP/POP3/SOAP
	reMailboxFail = regexp.MustCompile(
		`^authentication failed for \[([^\]]+)\]`,
	)

	// "user user@domain.com authenticated, mechanism=LOGIN [TLS]"  — IMAP/POP3/SOAP
	reMailboxSuccess = regexp.MustCompile(
		`^user\s+(\S+@\S+)\s+authenticated`,
	)

	// "Authentication successful for user: user@domain.com"  — protocolo "account" (admin SOAP, ActiveSync, etc.)
	reAccountSuccess = regexp.MustCompile(
		`^Authentication successful for user:\s+(\S+)`,
	)

	// "authentication failed for user user@domain.com: ..."  — protocolo "account"
	// Zimbra también puede emitir: "Authentication failed for [user@domain.com]"
	reAccountFail = regexp.MustCompile(
		`^[Aa]uthentication failed for(?:\s+user)?\s+[\[]?([^\]:,\s]+)`,
	)
)

// ── Parser ───────────────────────────────────────────────────────────────────

// queueTTL es el tiempo máximo que un queue ID autenticado permanece en caché
// sin que llegue el evento qmgr correspondiente. Evita la acumulación de memoria
// si el mensaje es rechazado o descartado antes de entrar en cola.
const queueTTL = 10 * time.Minute

// pruneEveryQueues controla cada cuántas llamadas a parseQmgr se limpian entradas expiradas.
const pruneEveryQueues = 500

// authedEntry registra la cuenta SASL y el timestamp de una auth exitosa pendiente
// de pasar por qmgr. Se necesita la cuenta para que los eventos RecipientAdded
// (reRcptFilter) lleven al remitente, no al destinatario.
type authedEntry struct {
	account string
	ts      time.Time
}

// senderEntry asocia un remitente autenticado con su timestamp de entrada en cola.
// Se usa para correlacionar eventos de bounce con la cuenta que envió el mensaje.
type senderEntry struct {
	account string
	ts      time.Time
}

// Parser convierte líneas de log en eventos tipados.
// Es stateful: mantiene dos mapas de queue IDs:
//   - authedQueues: QIDs entre auth SASL y qmgr (correo saliente en tránsito)
//   - queueSenders: QIDs ya en cola → cuenta remitente (para correlacionar bounces)
//
// Solo ParseLine accede a estos mapas; no hay acceso concurrente.
type Parser struct {
	authedQueues map[string]authedEntry // queueID → {account, timestamp} de auth SASL
	queueSenders map[string]senderEntry // queueID → cuenta del remitente autenticado
	queueCallCnt int
}

// New crea un Parser listo para usar.
func New() *Parser {
	return &Parser{
		authedQueues: make(map[string]authedEntry),
		queueSenders: make(map[string]senderEntry),
	}
}

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

	// Protocolos de interés: IMAP, POP3, SOAP (webmail), account (admin SOAP/ActiveSync).
	switch strings.ToLower(protocol) {
	case "imap", "pop3", "soap":
		return p.parseMailboxProtocol(ev, msg)
	case "account":
		return p.parseAccountProtocol(ev, msg)
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

// parseAccountProtocol maneja el protocolo "account" de mailbox.log.
// Cubre autenticaciones vía Admin SOAP (puerto 7073), ActiveSync y similares.
// Los mensajes usan capitalización distinta a los de IMAP/POP3.
func (p *Parser) parseAccountProtocol(ev event.Event, msg string) (event.Event, bool) {
	if m := reAccountSuccess.FindStringSubmatch(msg); m != nil {
		ev.Type = event.AuthSuccess
		ev.Account = m[1]
		ev.Domain = extractDomain(m[1])
		return ev, true
	}

	if m := reAccountFail.FindStringSubmatch(msg); m != nil {
		ev.Type = event.AuthFailed
		account := strings.Trim(m[1], "[]")
		if ev.Account == "" && account != "" {
			ev.Account = account
			ev.Domain = extractDomain(account)
		}
		return ev, true
	}

	return event.Event{}, false
}

// ── Helpers de mail.log ──────────────────────────────────────────────────────

func (p *Parser) parseSmtpd(ev event.Event, msg string) (event.Event, bool) {
	if m := reSaslFail.FindStringSubmatch(msg); m != nil {
		ev.Type = event.AuthFailed
		ev.IP = m[1]
		reason := m[2]
		if reason != "" {
			ev.Extra = map[string]string{"reason": reason}
			// Postfix moderno añade "sasl_username=X" al reason. Extraerlo si está presente.
			if i := strings.Index(reason, "sasl_username="); i >= 0 {
				username := reason[i+len("sasl_username="):]
				if j := strings.IndexAny(username, " ,;"); j >= 0 {
					username = username[:j]
				}
				if username != "" {
					ev.Account = username
					ev.Domain = extractDomain(username)
				}
			}
		}
		return ev, true
	}

	if m := reSaslSuccess.FindStringSubmatch(msg); m != nil {
		ev.Type = event.AuthSuccess
		ev.QueueID = m[1]
		ev.IP = m[2]
		ev.Account = m[3]
		ev.Domain = extractDomain(m[3])
		// Guardar cuenta además del timestamp para que reRcptFilter pueda asociar
		// el remitente (sasl_username) a cada destinatario RCPT, no el destinatario mismo.
		p.authedQueues[m[1]] = authedEntry{account: m[3], ts: ev.Timestamp}
		return ev, true
	}

	if m := reRcptFilter.FindStringSubmatch(msg); m != nil {
		// Solo emitir RecipientAdded para conexiones autenticadas.
		// Las entregas MX entrantes (ej: sunat.gob.pe) no pasan por SASL.
		entry, ok := p.authedQueues[m[1]]
		if !ok {
			return event.Event{}, false
		}
		ev.Type = event.RecipientAdded
		ev.QueueID = m[1]
		ev.IP = m[2]
		// Usar el remitente autenticado (sasl_username), no el destinatario RCPT TO.
		// Esto permite que rcptflood suspenda la cuenta comprometida correctamente.
		ev.Account = entry.account
		ev.Domain = extractDomain(entry.account)
		return ev, true
	}

	return event.Event{}, false
}

func (p *Parser) parseQmgr(ev event.Event, msg string) (event.Event, bool) {
	m := reQmgrFrom.FindStringSubmatch(msg)
	if m == nil {
		return event.Event{}, false
	}

	queueID := m[1]

	// Verificar si el mensaje fue enviado por un usuario autenticado vía SASL.
	// Los mensajes entrantes por MX (ej: sunat.gob.pe enviando a clientes locales)
	// NO tienen entrada en authedQueues y deben ignorarse para evitar falsos positivos.
	authEntry, authed := p.authedQueues[queueID]
	if authed {
		delete(p.authedQueues, queueID)
	}

	// Purga lazy: eliminar queue IDs autenticados que nunca llegaron a qmgr (rechazados, etc.)
	p.queueCallCnt++
	if p.queueCallCnt >= pruneEveryQueues {
		p.queueCallCnt = 0
		p.pruneQueues(ev.Timestamp)
	}

	if !authed {
		return event.Event{}, false
	}

	ev.Type = event.QueueAccepted
	ev.QueueID = queueID
	ev.Account = m[2]
	ev.Domain = extractDomain(m[2])
	ev.Extra = map[string]string{
		"size":  m[3],
		"nrcpt": m[4],
	}
	// Guardar cuenta para correlacionar bounces posteriores en parseDelivery.
	if m[2] != "" {
		p.queueSenders[queueID] = senderEntry{account: m[2], ts: authEntry.ts}
	}
	return ev, true
}

// pruneQueues elimina queue IDs expirados de ambos mapas.
// authedQueues: TTL corto (queueTTL=10 min) — cubre el tiempo entre auth y qmgr.
// queueSenders: TTL largo (30 min) — cubre mensajes con muchos destinatarios
// cuyas entregas se distribuyen en el tiempo.
func (p *Parser) pruneQueues(now time.Time) {
	cutoff := now.Add(-queueTTL)
	for qid, entry := range p.authedQueues {
		if entry.ts.Before(cutoff) {
			delete(p.authedQueues, qid)
		}
	}
	senderCutoff := now.Add(-30 * time.Minute)
	for qid, entry := range p.queueSenders {
		if entry.ts.Before(senderCutoff) {
			delete(p.queueSenders, qid)
		}
	}
}

func (p *Parser) parseDelivery(ev event.Event, msg string) (event.Event, bool) {
	m := reDelivery.FindStringSubmatch(msg)
	if m == nil {
		return event.Event{}, false
	}

	p.queueCallCnt++
	if p.queueCallCnt >= pruneEveryQueues {
		p.queueCallCnt = 0
		p.pruneQueues(ev.Timestamp)
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
		// Correlacionar bounce con la cuenta del remitente autenticado.
		if entry, ok := p.queueSenders[m[1]]; ok {
			ev.Account = entry.account
			ev.Domain = extractDomain(entry.account)
		}
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
