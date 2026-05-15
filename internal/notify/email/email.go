// Package email implementa notificaciones usando el sendmail local de Zimbra.
// No requiere configuración SMTP — usa /opt/zimbra/common/sbin/sendmail directamente.
package email

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/perulinux/sendguard/internal/detection"
)

const defaultSendmail = "/opt/zimbra/common/sbin/sendmail"

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
	fmt.Fprintf(&sb, "From: SendGuard <%s>\r\n", n.cfg.From)
	fmt.Fprintf(&sb, "To: %s\r\n", strings.Join(n.cfg.To, ", "))
	fmt.Fprintf(&sb, "Subject: %s\r\n", formatSubject(alert))
	fmt.Fprintf(&sb, "MIME-Version: 1.0\r\n")
	fmt.Fprintf(&sb, "Content-Type: text/plain; charset=utf-8\r\n")
	fmt.Fprintf(&sb, "\r\n")

	fmt.Fprintf(&sb, "SendGuard — Alerta de seguridad\n")
	fmt.Fprintf(&sb, "================================\n\n")
	fmt.Fprintf(&sb, "Fecha/Hora : %s\n", ts.Format("2006-01-02 15:04:05 -07:00"))
	fmt.Fprintf(&sb, "Módulo     : %s\n", alert.Module)
	fmt.Fprintf(&sb, "Acción     : %s\n", actionLabel(alert.Action))
	fmt.Fprintf(&sb, "Severidad  : %s (score: %d)\n", severityLabel(alert.Severity), alert.Score)
	if alert.Server != "" {
		fmt.Fprintf(&sb, "Servidor   : %s\n", alert.Server)
	}
	if alert.IP != "" {
		fmt.Fprintf(&sb, "IP         : %s\n", alert.IP)
	}
	if alert.Account != "" {
		fmt.Fprintf(&sb, "Cuenta     : %s\n", alert.Account)
	}
	if alert.Domain != "" {
		fmt.Fprintf(&sb, "Dominio    : %s\n", alert.Domain)
	}
	if len(alert.Reasons) > 0 {
		fmt.Fprintf(&sb, "\nDetalle:\n")
		for _, r := range alert.Reasons {
			fmt.Fprintf(&sb, "  • %s\n", r)
		}
	}
	fmt.Fprintf(&sb, "\n--\nSendGuard Agent\n")
	return sb.String()
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
		return "CRITICO"
	case detection.SeverityRateLimit:
		return "ALTO"
	case detection.SeverityWarn:
		return "MEDIO"
	default:
		return "INFO"
	}
}

func actionLabel(a detection.Action) string {
	switch a {
	case detection.ActionBlockIP:
		return "IP bloqueada"
	case detection.ActionSuspendAcct:
		return "Cuenta suspendida"
	case detection.ActionRateLimit:
		return "Rate-limit aplicado"
	case detection.ActionPurgeQueue:
		return "Cola purgada"
	default:
		return "Notificacion"
	}
}
