// Package email implementa notificaciones usando el sendmail local de Zimbra.
// No requiere configuración SMTP — usa /opt/zimbra/common/sbin/sendmail directamente.
package email

import (
	"bytes"
	"context"
	"fmt"
	"html"
	"os/exec"
	"strings"
	"time"

	"github.com/perulinux/sendguard/internal/detection"
)

const defaultSendmail = "/opt/zimbra/common/sbin/sendmail"

const mimeBoundary = "sendguard_boundary_4f8a2b1c"

// Config agrupa los parámetros del notificador de email.
type Config struct {
	From        string   // dirección remitente (requerido)
	To          []string // destinatarios (al menos uno requerido)
	SendmailBin string   // ruta al sendmail (default: /opt/zimbra/common/sbin/sendmail)
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
	return &Notifier{cfg: cfg}
}

// Notify formatea la alerta y la envía por correo.
func (n *Notifier) Notify(ctx context.Context, alert detection.Alert) error {
	if len(n.cfg.To) == 0 || n.cfg.From == "" {
		return nil
	}

	msg := n.buildMessage(alert)

	args := append([]string{"-f", n.cfg.From}, n.cfg.To...)
	cmd := exec.CommandContext(ctx, n.cfg.SendmailBin, args...)
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
	fmt.Fprintf(&sb, "Subject: %s\r\n", formatSubject(alert))
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

// buildPlain genera el cuerpo en texto plano (clientes sin HTML).
func buildPlain(alert detection.Alert, ts time.Time) string {
	var sb strings.Builder
	sev := severityLabel(alert.Severity)
	act := actionLabel(alert.Action)

	fmt.Fprintf(&sb, "SendGuard — Alerta de Seguridad [%s]\n", sev)
	fmt.Fprintf(&sb, "================================================\n\n")
	fmt.Fprintf(&sb, "Fecha/Hora  : %s\n", ts.Format("2006-01-02 15:04:05 -07:00"))
	fmt.Fprintf(&sb, "Módulo      : %s\n", alert.Module)
	fmt.Fprintf(&sb, "Acción      : %s\n", act)
	fmt.Fprintf(&sb, "Severidad   : %s (score: %d)\n", sev, alert.Score)
	if alert.Server != "" {
		fmt.Fprintf(&sb, "Servidor    : %s\n", alert.Server)
	}
	if alert.IP != "" {
		fmt.Fprintf(&sb, "IP          : %s\n", alert.IP)
	}
	if alert.Account != "" {
		fmt.Fprintf(&sb, "Cuenta      : %s\n", alert.Account)
	}
	if alert.Domain != "" {
		fmt.Fprintf(&sb, "Dominio     : %s\n", alert.Domain)
	}
	if len(alert.Reasons) > 0 {
		fmt.Fprintf(&sb, "\nDetalle:\n")
		for _, r := range alert.Reasons {
			fmt.Fprintf(&sb, "  • %s\n", r)
		}
	}
	fmt.Fprintf(&sb, "\n— SendGuard Agent\n")
	return sb.String()
}

// buildHTML genera el cuerpo en HTML con diseño de tarjeta.
func buildHTML(alert detection.Alert, ts time.Time) string {
	sev := severityLabel(alert.Severity)
	sevColor := severityColor(alert.Severity)
	sevBg := severityBg(alert.Severity)
	act := actionLabel(alert.Action)
	actionIcon := actionIcon(alert.Action)

	var rows strings.Builder
	addRow := func(label, value string) {
		if value == "" {
			return
		}
		fmt.Fprintf(&rows,
			`<tr><td style="padding:10px 16px;color:#6b7280;font-size:13px;white-space:nowrap;border-bottom:1px solid #f3f4f6;">%s</td>`+
				`<td style="padding:10px 16px;color:#111827;font-size:13px;border-bottom:1px solid #f3f4f6;word-break:break-all;">%s</td></tr>`,
			label, html.EscapeString(value))
	}

	addRow("Fecha / Hora", ts.Format("2006-01-02 15:04:05 -07:00"))
	addRow("Módulo", alert.Module)
	addRow("Servidor", alert.Server)
	addRow("IP atacante", alert.IP)
	addRow("Cuenta", alert.Account)
	addRow("Dominio", alert.Domain)

	var reasonsHTML string
	if len(alert.Reasons) > 0 {
		var rb strings.Builder
		rb.WriteString(`<ul style="margin:8px 0 0 0;padding-left:20px;color:#374151;font-size:13px;line-height:1.8;">`)
		for _, r := range alert.Reasons {
			fmt.Fprintf(&rb, `<li>%s</li>`, html.EscapeString(r))
		}
		rb.WriteString(`</ul>`)
		reasonsHTML = fmt.Sprintf(`
		<div style="margin:0 24px 24px 24px;background:#f9fafb;border-left:4px solid %s;border-radius:4px;padding:14px 16px;">
			<p style="margin:0;font-size:12px;font-weight:600;color:#6b7280;text-transform:uppercase;letter-spacing:.05em;">Detalle del evento</p>
			%s
		</div>`, sevColor, rb.String())
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="es">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>SendGuard Alerta</title></head>
<body style="margin:0;padding:0;background:#f3f4f6;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;">
<table width="100%%" cellpadding="0" cellspacing="0" style="background:#f3f4f6;padding:32px 16px;">
<tr><td align="center">
<table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%%;background:#ffffff;border-radius:12px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.08);">

  <!-- CABECERA -->
  <tr><td style="background:%s;padding:28px 24px;">
    <table width="100%%" cellpadding="0" cellspacing="0">
    <tr>
      <td>
        <p style="margin:0;font-size:11px;font-weight:700;color:rgba(255,255,255,.6);text-transform:uppercase;letter-spacing:.1em;">Alerta de Seguridad</p>
        <h1 style="margin:4px 0 0 0;font-size:22px;font-weight:700;color:#ffffff;">&#x1F6E1;&#xFE0F; SendGuard</h1>
      </td>
      <td align="right">
        <span style="display:inline-block;background:rgba(255,255,255,.15);color:#ffffff;font-size:11px;font-weight:700;padding:4px 12px;border-radius:20px;letter-spacing:.08em;text-transform:uppercase;">%s</span>
      </td>
    </tr>
    </table>
  </td></tr>

  <!-- BADGE DE ACCIÓN -->
  <tr><td style="background:%s;padding:16px 24px;border-bottom:3px solid %s;">
    <p style="margin:0;font-size:20px;font-weight:700;color:%s;">%s %s</p>
    <p style="margin:4px 0 0 0;font-size:13px;color:%s;opacity:.8;">Score de riesgo: <strong>%d / 100</strong></p>
  </td></tr>

  <!-- TABLA DE DETALLES -->
  <tr><td style="padding:8px 0 0 0;">
    <table width="100%%" cellpadding="0" cellspacing="0">
      %s
    </table>
  </td></tr>

  <!-- RAZONES -->
  %s

  <!-- FOOTER -->
  <tr><td style="background:#f9fafb;padding:16px 24px;border-top:1px solid #e5e7eb;">
    <p style="margin:0;font-size:12px;color:#9ca3af;text-align:center;">
      Generado por <strong>SendGuard Agent</strong> &mdash; Sistema de protección para Zimbra<br>
      <span style="font-size:11px;">%s</span>
    </p>
  </td></tr>

</table>
</td></tr>
</table>
</body>
</html>`,
		headerColor(alert.Severity),     // cabecera bg
		sev,                              // badge severidad
		sevBg, sevColor,                  // acción bg / border
		sevColor,                         // acción texto color
		actionIcon, html.EscapeString(act), // icono + texto acción
		sevColor,                         // score color
		alert.Score,                      // score valor
		rows.String(),                    // filas de detalles
		reasonsHTML,                      // bloque razones
		ts.Format("2006-01-02 15:04:05 -07:00"), // timestamp footer
	)
}

func formatSubject(alert detection.Alert) string {
	target := alert.IP
	if target == "" {
		target = alert.Account
	}
	if target == "" {
		target = alert.Domain
	}
	server := alert.Server
	if server == "" {
		server = "sendguard"
	}
	return fmt.Sprintf("[SendGuard][%s] %s — %s (%s)",
		severityLabel(alert.Severity), actionLabel(alert.Action), target, server)
}

func severityLabel(s detection.Severity) string {
	switch s {
	case detection.SeveritySuspend:
		return "CRÍTICO"
	case detection.SeverityRateLimit:
		return "ALTO"
	case detection.SeverityWarn:
		return "MEDIO"
	default:
		return "INFO"
	}
}

func severityColor(s detection.Severity) string {
	switch s {
	case detection.SeveritySuspend:
		return "#dc2626"
	case detection.SeverityRateLimit:
		return "#ea580c"
	case detection.SeverityWarn:
		return "#d97706"
	default:
		return "#2563eb"
	}
}

func severityBg(s detection.Severity) string {
	switch s {
	case detection.SeveritySuspend:
		return "#fef2f2"
	case detection.SeverityRateLimit:
		return "#fff7ed"
	case detection.SeverityWarn:
		return "#fffbeb"
	default:
		return "#eff6ff"
	}
}

func headerColor(s detection.Severity) string {
	switch s {
	case detection.SeveritySuspend:
		return "#991b1b"
	case detection.SeverityRateLimit:
		return "#9a3412"
	case detection.SeverityWarn:
		return "#92400e"
	default:
		return "#1e40af"
	}
}

func actionIcon(a detection.Action) string {
	switch a {
	case detection.ActionBlockIP:
		return "&#x1F6AB;"
	case detection.ActionSuspendAcct:
		return "&#x1F512;"
	case detection.ActionRateLimit:
		return "&#x23F3;"
	case detection.ActionPurgeQueue:
		return "&#x1F9F9;"
	default:
		return "&#x2139;&#xFE0F;"
	}
}

func actionLabel(a detection.Action) string {
	switch a {
	case detection.ActionBlockIP:
		return "IP bloqueada en firewall"
	case detection.ActionSuspendAcct:
		return "Cuenta suspendida"
	case detection.ActionRateLimit:
		return "Rate-limit aplicado"
	case detection.ActionPurgeQueue:
		return "Cola de correo purgada"
	default:
		return "Notificación"
	}
}
