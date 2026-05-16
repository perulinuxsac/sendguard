// Package report genera y envía el resumen diario de actividad de SendGuard.
// Usa el sendmail local de Zimbra (igual que el notificador de email), sin
// requerir configuración SMTP adicional.
package report

import (
	"bytes"
	"context"
	"fmt"
	"html"
	"log/slog"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/perulinux/sendguard/internal/detection"
	"github.com/perulinux/sendguard/internal/enforcement"
)

const defaultSendmail = "/opt/zimbra/common/sbin/sendmail"
const mimeBoundary = "sendguard_report_boundary_7c3d1e"

// EnforcerView es el subconjunto del Enforcer que el reporter necesita.
type EnforcerView interface {
	BlockedIPs() []enforcement.BlockedIPInfo
	SuspendedAccounts() []enforcement.SuspendedAcctInfo
	Stats() enforcement.EnforcerStats
}

// EngineView es el subconjunto del Engine que el reporter necesita.
type EngineView interface {
	EventsTotal() int64
	AlertsTotal() int64
	ModuleStats() []detection.ModuleStat
}

// Config agrupa los parámetros del reporter.
type Config struct {
	Hour        int      // hora UTC en la que enviar el reporte (0-23, default 8)
	EmailFrom   string   // remitente
	EmailTo     []string // destinatarios
	SendmailBin string   // ruta a sendmail (default: /opt/zimbra/common/sbin/sendmail)
	ServerID    string   // identificador del servidor (aparece en el asunto)
	ClientName  string   // nombre del cliente (aparece en la cabecera)
}

// Reporter envía el resumen diario a la hora configurada.
type Reporter struct {
	cfg      Config
	enforcer EnforcerView
	engine   EngineView
}

// New crea un Reporter con la configuración y las dependencias dadas.
func New(cfg Config, enforcer EnforcerView, engine EngineView) *Reporter {
	if cfg.SendmailBin == "" {
		cfg.SendmailBin = defaultSendmail
	}
	if cfg.Hour < 0 || cfg.Hour > 23 {
		cfg.Hour = 8
	}
	return &Reporter{cfg: cfg, enforcer: enforcer, engine: engine}
}

// Run bloquea hasta que ctx sea cancelado, enviando el reporte una vez al día
// a la hora configurada (UTC).
func (r *Reporter) Run(ctx context.Context) {
	for {
		next := nextScheduled(time.Now().UTC(), r.cfg.Hour)
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Until(next)):
		}
		if err := r.Send(ctx); err != nil {
			slog.Warn("report: error enviando resumen diario", "error", err)
		}
	}
}

// Send construye y envía el resumen inmediatamente (útil para testing o envío manual).
func (r *Reporter) Send(ctx context.Context) error {
	if len(r.cfg.EmailTo) == 0 || r.cfg.EmailFrom == "" {
		return nil
	}
	msg := r.buildMessage()
	args := append([]string{"-f", r.cfg.EmailFrom}, r.cfg.EmailTo...)
	cmd := exec.CommandContext(ctx, r.cfg.SendmailBin, args...)
	cmd.Stdin = bytes.NewBufferString(msg)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("sendmail: %w — %s", err, strings.TrimSpace(string(out)))
	}
	slog.Info("report: resumen diario enviado", "to", r.cfg.EmailTo)
	return nil
}

// nextScheduled calcula la próxima hora H:00 UTC que no haya pasado aún.
func nextScheduled(now time.Time, hour int) time.Time {
	t := time.Date(now.Year(), now.Month(), now.Day(), hour, 0, 0, 0, time.UTC)
	if !t.After(now) {
		t = t.Add(24 * time.Hour)
	}
	return t
}

func (r *Reporter) buildMessage() string {
	now := time.Now().UTC()
	enfStats := r.enforcer.Stats()
	blocked := r.enforcer.BlockedIPs()
	suspended := r.enforcer.SuspendedAccounts()
	modStats := r.engine.ModuleStats()

	sort.Slice(modStats, func(i, j int) bool {
		return modStats[i].Alerts > modStats[j].Alerts
	})

	var sb strings.Builder
	subject := fmt.Sprintf("[SendGuard] Resumen diario — %s (%s)",
		r.cfg.ServerID, now.Format("2006-01-02"))

	fmt.Fprintf(&sb, "From: SendGuard <%s>\r\n", r.cfg.EmailFrom)
	fmt.Fprintf(&sb, "To: %s\r\n", strings.Join(r.cfg.EmailTo, ", "))
	fmt.Fprintf(&sb, "Subject: %s\r\n", subject)
	fmt.Fprintf(&sb, "MIME-Version: 1.0\r\n")
	fmt.Fprintf(&sb, "Content-Type: multipart/alternative; boundary=\"%s\"\r\n\r\n", mimeBoundary)

	// Texto plano
	fmt.Fprintf(&sb, "--%s\r\n", mimeBoundary)
	fmt.Fprintf(&sb, "Content-Type: text/plain; charset=utf-8\r\n\r\n")
	sb.WriteString(r.buildPlain(now, enfStats, blocked, suspended, modStats))
	fmt.Fprintf(&sb, "\r\n")

	// HTML
	fmt.Fprintf(&sb, "--%s\r\n", mimeBoundary)
	fmt.Fprintf(&sb, "Content-Type: text/html; charset=utf-8\r\n\r\n")
	sb.WriteString(r.buildHTML(now, enfStats, blocked, suspended, modStats))
	fmt.Fprintf(&sb, "\r\n")

	fmt.Fprintf(&sb, "--%s--\r\n", mimeBoundary)
	return sb.String()
}

func (r *Reporter) buildPlain(now time.Time, stats enforcement.EnforcerStats,
	blocked []enforcement.BlockedIPInfo, suspended []enforcement.SuspendedAcctInfo,
	mods []detection.ModuleStat) string {

	var sb strings.Builder
	fmt.Fprintf(&sb, "SendGuard — Resumen Diario\n")
	fmt.Fprintf(&sb, "Servidor : %s\n", r.cfg.ServerID)
	fmt.Fprintf(&sb, "Fecha    : %s\n\n", now.Format("2006-01-02 15:04 UTC"))

	fmt.Fprintf(&sb, "CONTADORES ACUMULADOS\n")
	fmt.Fprintf(&sb, "  Eventos procesados : %d\n", r.engine.EventsTotal())
	fmt.Fprintf(&sb, "  Alertas emitidas   : %d\n", r.engine.AlertsTotal())
	fmt.Fprintf(&sb, "  IPs bloqueadas     : %d\n", stats.BlocksTotal)
	fmt.Fprintf(&sb, "  Cuentas suspendidas: %d\n\n", stats.SuspensionsTotal)

	fmt.Fprintf(&sb, "ESTADO ACTUAL\n")
	fmt.Fprintf(&sb, "  IPs bloqueadas activas : %d\n", len(blocked))
	fmt.Fprintf(&sb, "  Cuentas suspendidas    : %d\n\n", len(suspended))

	if len(mods) > 0 {
		fmt.Fprintf(&sb, "ACTIVIDAD POR MÓDULO\n")
		for _, m := range mods {
			fmt.Fprintf(&sb, "  %-22s %d alertas\n", m.Module, m.Alerts)
		}
		fmt.Fprintf(&sb, "\n")
	}

	if len(blocked) > 0 {
		fmt.Fprintf(&sb, "IPs BLOQUEADAS ACTUALMENTE\n")
		for _, b := range blocked {
			fmt.Fprintf(&sb, "  %-18s  módulo: %s\n", b.IP, b.Module)
		}
		fmt.Fprintf(&sb, "\n")
	}

	if len(suspended) > 0 {
		fmt.Fprintf(&sb, "CUENTAS SUSPENDIDAS\n")
		for _, s := range suspended {
			fmt.Fprintf(&sb, "  %s  (módulo: %s)\n", s.Account, s.Module)
		}
		fmt.Fprintf(&sb, "\n")
	}

	fmt.Fprintf(&sb, "— SendGuard Agent\n")
	return sb.String()
}

func (r *Reporter) buildHTML(now time.Time, stats enforcement.EnforcerStats,
	blocked []enforcement.BlockedIPInfo, suspended []enforcement.SuspendedAcctInfo,
	mods []detection.ModuleStat) string {

	clientLabel := r.cfg.ClientName
	if clientLabel == "" {
		clientLabel = r.cfg.ServerID
	}

	// Tarjetas de resumen
	cards := fmt.Sprintf(`
	<table cellpadding="0" cellspacing="0" width="100%%">
	<tr>
	  %s%s%s%s
	</tr>
	</table>`,
		statCard("Eventos", fmt.Sprintf("%d", r.engine.EventsTotal()), "#2563eb", "&#x1F4CA;"),
		statCard("Alertas", fmt.Sprintf("%d", r.engine.AlertsTotal()), "#7c3aed", "&#x26A0;&#xFE0F;"),
		statCard("IPs bloqueadas", fmt.Sprintf("%d total / %d activas", stats.BlocksTotal, len(blocked)), "#dc2626", "&#x1F6AB;"),
		statCard("Cuentas", fmt.Sprintf("%d susp. / %d activas", stats.SuspensionsTotal, len(suspended)), "#d97706", "&#x1F512;"),
	)

	// Tabla de módulos
	var modsHTML string
	if len(mods) > 0 {
		var rows strings.Builder
		for i, m := range mods {
			bg := "#ffffff"
			if i%2 == 1 {
				bg = "#f9fafb"
			}
			fmt.Fprintf(&rows,
				`<tr style="background:%s;">
				  <td style="padding:10px 16px;font-size:13px;color:#374151;font-family:monospace;">%s</td>
				  <td style="padding:10px 16px;font-size:13px;color:#111827;text-align:right;font-weight:600;">%d</td>
				</tr>`,
				bg, html.EscapeString(m.Module), m.Alerts)
		}
		modsHTML = fmt.Sprintf(`
		<div style="margin:0 24px 24px 24px;">
		  <p style="margin:0 0 10px 0;font-size:12px;font-weight:700;color:#6b7280;text-transform:uppercase;letter-spacing:.08em;">Actividad por módulo</p>
		  <table width="100%%" cellpadding="0" cellspacing="0" style="border-radius:8px;overflow:hidden;border:1px solid #e5e7eb;">
		    <tr style="background:#f3f4f6;">
		      <th style="padding:8px 16px;font-size:11px;color:#6b7280;text-align:left;font-weight:600;text-transform:uppercase;">Módulo</th>
		      <th style="padding:8px 16px;font-size:11px;color:#6b7280;text-align:right;font-weight:600;text-transform:uppercase;">Alertas</th>
		    </tr>
		    %s
		  </table>
		</div>`, rows.String())
	}

	// Lista de IPs bloqueadas (max 15)
	var blockedHTML string
	if len(blocked) > 0 {
		limit := len(blocked)
		if limit > 15 {
			limit = 15
		}
		var rows strings.Builder
		for i := 0; i < limit; i++ {
			b := blocked[i]
			ttl := time.Until(b.Expiry)
			ttlStr := ttl.Truncate(time.Second).String()
			if ttl > 365*24*time.Hour {
				ttlStr = "permanente"
			}
			bg := "#ffffff"
			if i%2 == 1 {
				bg = "#fef2f2"
			}
			fmt.Fprintf(&rows,
				`<tr style="background:%s;">
				  <td style="padding:8px 16px;font-size:12px;color:#111827;font-family:monospace;">%s</td>
				  <td style="padding:8px 16px;font-size:12px;color:#6b7280;">%s</td>
				  <td style="padding:8px 16px;font-size:12px;color:#9ca3af;text-align:right;">%s</td>
				</tr>`,
				bg, html.EscapeString(b.IP), html.EscapeString(b.Module), ttlStr)
		}
		extra := ""
		if len(blocked) > 15 {
			extra = fmt.Sprintf(`<tr><td colspan="3" style="padding:8px 16px;font-size:12px;color:#9ca3af;text-align:center;">… y %d más</td></tr>`, len(blocked)-15)
		}
		blockedHTML = fmt.Sprintf(`
		<div style="margin:0 24px 24px 24px;">
		  <p style="margin:0 0 10px 0;font-size:12px;font-weight:700;color:#6b7280;text-transform:uppercase;letter-spacing:.08em;">IPs bloqueadas actualmente (%d)</p>
		  <table width="100%%" cellpadding="0" cellspacing="0" style="border-radius:8px;overflow:hidden;border:1px solid #fecaca;">
		    <tr style="background:#fef2f2;">
		      <th style="padding:6px 16px;font-size:11px;color:#6b7280;text-align:left;text-transform:uppercase;">IP</th>
		      <th style="padding:6px 16px;font-size:11px;color:#6b7280;text-align:left;text-transform:uppercase;">Módulo</th>
		      <th style="padding:6px 16px;font-size:11px;color:#6b7280;text-align:right;text-transform:uppercase;">TTL</th>
		    </tr>
		    %s%s
		  </table>
		</div>`, len(blocked), rows.String(), extra)
	}

	// Lista de cuentas suspendidas
	var suspHTML string
	if len(suspended) > 0 {
		var rows strings.Builder
		for i, s := range suspended {
			bg := "#ffffff"
			if i%2 == 1 {
				bg = "#fffbeb"
			}
			fmt.Fprintf(&rows,
				`<tr style="background:%s;">
				  <td style="padding:8px 16px;font-size:12px;color:#111827;">%s</td>
				  <td style="padding:8px 16px;font-size:12px;color:#6b7280;">%s</td>
				  <td style="padding:8px 16px;font-size:12px;color:#9ca3af;text-align:right;">%s</td>
				</tr>`,
				bg, html.EscapeString(s.Account), html.EscapeString(s.Module),
				s.Timestamp.Local().Format("15:04"))
		}
		suspHTML = fmt.Sprintf(`
		<div style="margin:0 24px 24px 24px;">
		  <p style="margin:0 0 10px 0;font-size:12px;font-weight:700;color:#6b7280;text-transform:uppercase;letter-spacing:.08em;">Cuentas suspendidas (%d)</p>
		  <table width="100%%" cellpadding="0" cellspacing="0" style="border-radius:8px;overflow:hidden;border:1px solid #fde68a;">
		    <tr style="background:#fffbeb;">
		      <th style="padding:6px 16px;font-size:11px;color:#6b7280;text-align:left;text-transform:uppercase;">Cuenta</th>
		      <th style="padding:6px 16px;font-size:11px;color:#6b7280;text-align:left;text-transform:uppercase;">Módulo</th>
		      <th style="padding:6px 16px;font-size:11px;color:#6b7280;text-align:right;text-transform:uppercase;">Hora</th>
		    </tr>
		    %s
		  </table>
		</div>`, len(suspended), rows.String())
	}

	noActivity := ""
	if len(mods) == 0 && len(blocked) == 0 && len(suspended) == 0 {
		noActivity = `<div style="margin:0 24px 24px 24px;padding:24px;text-align:center;background:#f0fdf4;border-radius:8px;border:1px solid #bbf7d0;">
		  <p style="margin:0;font-size:14px;color:#166534;">&#x2705; Sin actividad de amenazas en las últimas 24 horas</p>
		</div>`
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="es">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>SendGuard Resumen Diario</title></head>
<body style="margin:0;padding:0;background:#f3f4f6;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;">
<table width="100%%" cellpadding="0" cellspacing="0" style="background:#f3f4f6;padding:32px 16px;">
<tr><td align="center">
<table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%%;background:#ffffff;border-radius:12px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.08);">

  <!-- CABECERA -->
  <tr><td style="background:#1e40af;padding:24px;">
    <table width="100%%" cellpadding="0" cellspacing="0"><tr>
      <td>
        <p style="margin:0;font-size:11px;font-weight:700;color:rgba(255,255,255,.6);text-transform:uppercase;letter-spacing:.1em;">Resumen Diario</p>
        <h1 style="margin:4px 0 0 0;font-size:20px;font-weight:700;color:#ffffff;">&#x1F6E1;&#xFE0F; SendGuard</h1>
      </td>
      <td align="right" style="text-align:right;">
        <p style="margin:0;font-size:12px;color:rgba(255,255,255,.7);">%s</p>
        <p style="margin:2px 0 0 0;font-size:11px;color:rgba(255,255,255,.5);">%s UTC</p>
      </td>
    </tr></table>
  </td></tr>

  <!-- TARJETAS DE RESUMEN -->
  <tr><td style="padding:24px 24px 8px 24px;">
    %s
  </td></tr>

  <!-- MÓDULOS / BLOQUEADAS / SUSPENDIDAS -->
  <tr><td style="padding:8px 0 0 0;">
    %s%s%s%s
  </td></tr>

  <!-- FOOTER -->
  <tr><td style="background:#f9fafb;padding:16px 24px;border-top:1px solid #e5e7eb;">
    <p style="margin:0;font-size:12px;color:#9ca3af;text-align:center;">
      <strong>SendGuard Agent</strong> &mdash; Protección automática para Zimbra<br>
      <span style="font-size:11px;">%s &bull; %s</span>
    </p>
  </td></tr>

</table>
</td></tr>
</table>
</body>
</html>`,
		html.EscapeString(clientLabel),
		now.Format("2006-01-02 15:04"),
		cards,
		noActivity, modsHTML, blockedHTML, suspHTML,
		html.EscapeString(r.cfg.ServerID),
		now.Format("2006-01-02"),
	)
}

func statCard(label, value, color, icon string) string {
	return fmt.Sprintf(`
	<td width="25%%" style="padding:0 6px;">
	  <div style="background:%s;border-radius:8px;padding:14px 12px;text-align:center;">
	    <p style="margin:0;font-size:20px;">%s</p>
	    <p style="margin:4px 0 2px 0;font-size:18px;font-weight:700;color:#ffffff;line-height:1.2;">%s</p>
	    <p style="margin:0;font-size:10px;color:rgba(255,255,255,.7);text-transform:uppercase;letter-spacing:.06em;">%s</p>
	  </div>
	</td>`, color, icon, html.EscapeString(value), html.EscapeString(label))
}
