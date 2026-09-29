// Package email implementa notificaciones usando el sendmail local de Zimbra.
// No requiere configuración SMTP — usa /opt/zimbra/common/sbin/sendmail directamente.
package email

import (
	"bytes"
	"context"
	"fmt"
	"html"
	"mime"
	"os/exec"
	"strings"
	"time"

	"github.com/perulinux/sendguard/internal/detection"
	"github.com/perulinux/sendguard/internal/notify/present"
)

const defaultSendmail = "/opt/zimbra/common/sbin/sendmail"

const mimeBoundary = "sendguard_boundary_4f8a2b1c"

// sendmailTimeout acota la ejecución de sendmail. Notify corre en el goroutine
// del enforcer: un sendmail colgado (postdrop sin espacio, maildrop trabado)
// congelaría todo el pipeline de contención. Var (no const) para poder
// acortarlo en tests.
var sendmailTimeout = 60 * time.Second

// Config agrupa los parámetros del notificador de email.
type Config struct {
	From        string   // dirección remitente (requerido)
	To          []string // destinatarios (al menos uno requerido)
	SendmailBin string   // ruta al sendmail (default: /opt/zimbra/common/sbin/sendmail)
	// UserNoticeFrom es el remitente del aviso al usuario suspendido y el
	// contacto de soporte mostrado en ese aviso. Default: From.
	UserNoticeFrom string
}

// Notifier envía alertas por correo usando el sendmail local de Zimbra.
type Notifier struct {
	cfg Config
}

// New crea un Notifier con la configuración dada.
func New(cfg Config) *Notifier {
	if cfg.SendmailBin == "" {
		cfg.SendmailBin = defaultSendmail
	}
	if cfg.UserNoticeFrom == "" {
		cfg.UserNoticeFrom = cfg.From
	}
	return &Notifier{cfg: cfg}
}

// Notify formatea la alerta y la envía por correo.
func (n *Notifier) Notify(ctx context.Context, alert detection.Alert) error {
	if len(n.cfg.To) == 0 || n.cfg.From == "" {
		return nil
	}

	msg := n.buildMessage(alert)

	ctx, cancel := context.WithTimeout(ctx, sendmailTimeout)
	defer cancel()

	args := append([]string{"-f", n.cfg.From}, n.cfg.To...)
	cmd := exec.CommandContext(ctx, n.cfg.SendmailBin, args...)
	// Sin WaitDelay, un hijo huérfano de sendmail (postdrop) que herede los
	// pipes mantendría Wait() bloqueado aunque el timeout mate a sendmail.
	cmd.WaitDelay = 2 * time.Second
	cmd.Stdin = bytes.NewBufferString(msg)

	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("email: sendmail: %w — %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (n *Notifier) buildMessage(alert detection.Alert) string {
	ts := alert.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}

	var sb strings.Builder

	// Headers MIME multipart
	fmt.Fprintf(&sb, "From: SendGuard <%s>\r\n", n.cfg.From)
	fmt.Fprintf(&sb, "To: %s\r\n", strings.Join(n.cfg.To, ", "))
	// RFC 2047: el asunto lleva tildes y emoji; sin codificar, algunos
	// clientes lo muestran roto.
	fmt.Fprintf(&sb, "Subject: %s\r\n", mime.QEncoding.Encode("utf-8", present.Subject(alert)))
	fmt.Fprintf(&sb, "MIME-Version: 1.0\r\n")
	fmt.Fprintf(&sb, "Content-Type: multipart/alternative; boundary=\"%s\"\r\n", mimeBoundary)
	fmt.Fprintf(&sb, "\r\n")

	// Parte 1: texto plano (fallback)
	fmt.Fprintf(&sb, "--%s\r\n", mimeBoundary)
	fmt.Fprintf(&sb, "Content-Type: text/plain; charset=utf-8\r\n")
	fmt.Fprintf(&sb, "\r\n")
	sb.WriteString(buildPlain(alert, ts))
	fmt.Fprintf(&sb, "\r\n")

	// Parte 2: HTML
	fmt.Fprintf(&sb, "--%s\r\n", mimeBoundary)
	fmt.Fprintf(&sb, "Content-Type: text/html; charset=utf-8\r\n")
	fmt.Fprintf(&sb, "\r\n")
	sb.WriteString(buildHTML(alert, ts))
	fmt.Fprintf(&sb, "\r\n")

	fmt.Fprintf(&sb, "--%s--\r\n", mimeBoundary)

	return sb.String()
}

// buildPlain genera el cuerpo en texto plano (clientes sin HTML). Misma
// estructura que el HTML y Telegram: resultado → qué pasó → acciones → origen
// → qué hacer.
func buildPlain(alert detection.Alert, ts time.Time) string {
	v := present.Build(alert)
	var sb strings.Builder

	fmt.Fprintf(&sb, "%s %s\n", v.Icon, v.Title)
	if v.Target != "" {
		fmt.Fprintf(&sb, "%s\n", v.Target)
	}
	sb.WriteString("================================================\n")
	if v.Next != "" {
		fmt.Fprintf(&sb, "\n>> %s\n", v.Next)
	}

	fmt.Fprintf(&sb, "\nQUÉ PASÓ  [%s · score %d/100]\n", present.SeverityLabel(alert.Severity), alert.Score)
	if v.What != "" {
		fmt.Fprintf(&sb, "%s\n", v.What)
	}
	for _, r := range alert.Reasons {
		fmt.Fprintf(&sb, "  • %s\n", r)
	}

	if len(alert.Effects) > 0 {
		sb.WriteString("\nACCIONES DEL AGENTE\n")
		for _, e := range alert.Effects {
			fmt.Fprintf(&sb, "  %s %s\n", present.EffectIcon(e.Outcome), e.Text)
		}
	}

	sb.WriteString("\nORIGEN\n")
	for _, kv := range originRows(alert, ts) {
		fmt.Fprintf(&sb, "  %-10s %s\n", kv[0]+":", kv[1])
	}

	if v.Revert != "" {
		fmt.Fprintf(&sb, "\nREVERTIR\n  %s\n", v.Revert)
	}
	fmt.Fprintf(&sb, "\n— SendGuard Agent\n")
	return sb.String()
}

// originRows son los datos de contexto de la alerta, en el orden en que se
// muestran. Omite los vacíos.
func originRows(alert detection.Alert, ts time.Time) [][2]string {
	var rows [][2]string
	add := func(k, v string) {
		if v != "" {
			rows = append(rows, [2]string{k, v})
		}
	}
	add("IP", alert.IP)
	add("País", present.Country(alert.Country))
	add("Cuenta", alert.Account)
	add("Dominio", alert.Domain)
	add("Servidor", alert.Server)
	add("Módulo", alert.Module)
	add("Fecha", ts.Format("2006-01-02 15:04:05 -07:00"))
	return rows
}

// palette son los colores de cada tono: acento, fondo suave y texto sobre fondo.
type palette struct{ accent, soft, ink string }

func tonePalette(t present.Tone) palette {
	switch t {
	case present.ToneFailed:
		return palette{"#991b1b", "#fee2e2", "#7f1d1d"}
	case present.ToneCritical:
		return palette{"#dc2626", "#fef2f2", "#991b1b"}
	case present.ToneHigh:
		return palette{"#ea580c", "#fff7ed", "#9a3412"}
	case present.ToneWarning:
		return palette{"#d97706", "#fffbeb", "#92400e"}
	case present.ToneMuted:
		return palette{"#6b7280", "#f3f4f6", "#374151"}
	default:
		return palette{"#2563eb", "#eff6ff", "#1e40af"}
	}
}

// effectColor colorea cada acción del agente según su resultado.
func effectColor(o detection.Outcome) string {
	switch o {
	case detection.OutcomeApplied:
		return "#15803d"
	case detection.OutcomeFailed:
		return "#b91c1c"
	case detection.OutcomeAlready:
		return "#4b5563"
	default:
		return "#b45309"
	}
}

// buildHTML genera el cuerpo HTML: tarjeta con el resultado real arriba, qué
// hacer, qué pasó, qué hizo el agente, origen y cómo revertir. Tablas y estilos
// en línea para que se vea igual en Outlook, Gmail y el webmail de Zimbra.
func buildHTML(alert detection.Alert, ts time.Time) string {
	v := present.Build(alert)
	p := tonePalette(v.Tone)
	esc := html.EscapeString

	section := func(title, body string) string {
		return fmt.Sprintf(`
  <tr><td style="padding:20px 28px 0 28px;">
    <p style="margin:0 0 8px 0;font-size:11px;font-weight:700;color:#6b7280;text-transform:uppercase;letter-spacing:.08em;">%s</p>
    %s
  </td></tr>`, title, body)
	}

	var body strings.Builder

	// Qué hacer (llamada a la acción) — lo primero después del título.
	if v.Next != "" {
		fmt.Fprintf(&body, `
  <tr><td style="padding:20px 28px 0 28px;">
    <div style="background:%s;border-left:4px solid %s;border-radius:6px;padding:12px 16px;font-size:14px;line-height:1.5;color:%s;">%s</div>
  </td></tr>`, p.soft, p.accent, p.ink, esc(v.Next))
	}

	// Qué pasó
	var what strings.Builder
	fmt.Fprintf(&what, `<p style="margin:0;font-size:15px;font-weight:600;color:#111827;">%s</p>`, esc(v.What))
	if len(alert.Reasons) > 0 {
		what.WriteString(`<ul style="margin:8px 0 0 0;padding-left:18px;color:#374151;font-size:13px;line-height:1.7;">`)
		for _, r := range alert.Reasons {
			fmt.Fprintf(&what, `<li>%s</li>`, esc(r))
		}
		what.WriteString(`</ul>`)
	}
	body.WriteString(section("Qué pasó", what.String()))

	// Acciones del agente
	if len(alert.Effects) > 0 {
		var acts strings.Builder
		acts.WriteString(`<table width="100%" cellpadding="0" cellspacing="0">`)
		for _, e := range alert.Effects {
			fmt.Fprintf(&acts,
				`<tr><td width="28" valign="top" style="padding:5px 0;font-size:15px;">%s</td>`+
					`<td style="padding:5px 0;font-size:14px;color:%s;line-height:1.5;">%s</td></tr>`,
				present.EffectIcon(e.Outcome), effectColor(e.Outcome), esc(e.Text))
		}
		acts.WriteString(`</table>`)
		body.WriteString(section("Acciones del agente", acts.String()))
	}

	// Origen
	var orig strings.Builder
	orig.WriteString(`<table width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #e5e7eb;border-radius:8px;">`)
	for i, kv := range originRows(alert, ts) {
		border := "border-top:1px solid #f3f4f6;"
		if i == 0 {
			border = ""
		}
		val := esc(kv[1])
		if kv[0] == "IP" || kv[0] == "Cuenta" {
			val = `<span style="font-family:SFMono-Regular,Consolas,monospace;">` + val + `</span>`
		}
		fmt.Fprintf(&orig,
			`<tr><td width="96" style="padding:9px 14px;color:#6b7280;font-size:13px;%s">%s</td>`+
				`<td style="padding:9px 14px;color:#111827;font-size:13px;word-break:break-all;%s">%s</td></tr>`,
			border, kv[0], border, val)
	}
	orig.WriteString(`</table>`)
	body.WriteString(section("Origen", orig.String()))

	// Cómo revertir
	if v.Revert != "" {
		body.WriteString(section("Cómo revertir", fmt.Sprintf(
			`<div style="background:#111827;color:#f9fafb;border-radius:6px;padding:10px 14px;font-family:SFMono-Regular,Consolas,monospace;font-size:13px;">%s</div>`,
			esc(v.Revert))))
	}

	target := ""
	if v.Target != "" {
		target = fmt.Sprintf(`<p style="margin:6px 0 0 0;font-family:SFMono-Regular,Consolas,monospace;font-size:15px;color:#ffffff;word-break:break-all;">%s</p>`, esc(v.Target))
	}
	server := "SendGuard"
	if alert.Server != "" {
		server = "SendGuard · " + esc(alert.Server)
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="es">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>%s</title></head>
<body style="margin:0;padding:0;background:#f3f4f6;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">
<table width="100%%" cellpadding="0" cellspacing="0" style="background:#f3f4f6;padding:28px 12px;">
<tr><td align="center">
<table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%%;background:#ffffff;border-radius:12px;overflow:hidden;box-shadow:0 2px 12px rgba(0,0,0,.06);">

  <!-- CABECERA: resultado real + objetivo -->
  <tr><td style="background:%s;padding:22px 28px;">
    <table width="100%%" cellpadding="0" cellspacing="0"><tr>
      <td><p style="margin:0;font-size:11px;font-weight:700;color:rgba(255,255,255,.75);text-transform:uppercase;letter-spacing:.1em;">%s</p></td>
      <td align="right"><span style="display:inline-block;background:rgba(255,255,255,.18);color:#ffffff;font-size:11px;font-weight:700;padding:3px 10px;border-radius:12px;letter-spacing:.06em;">%s · %d/100</span></td>
    </tr></table>
    <h1 style="margin:10px 0 0 0;font-size:22px;line-height:1.3;font-weight:700;color:#ffffff;">%s %s</h1>
    %s
  </td></tr>
%s
  <!-- PIE -->
  <tr><td style="padding:24px 28px 22px 28px;">
    <p style="margin:0;border-top:1px solid #e5e7eb;padding-top:14px;font-size:11px;color:#9ca3af;text-align:center;">
      SendGuard Agent — protección para Zimbra · %s
    </p>
  </td></tr>

</table>
</td></tr>
</table>
</body>
</html>`,
		esc(v.Title),
		p.accent,
		server,
		present.SeverityLabel(alert.Severity), alert.Score,
		v.Icon, esc(v.Title),
		target,
		body.String(),
		ts.Format("2006-01-02 15:04:05 -07:00"),
	)
}
