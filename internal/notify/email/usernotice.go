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

// NotifySuspendedUser envía un aviso al propio usuario cuya cuenta fue
// suspendida por compromiso. A diferencia de Notify (alerta técnica para
// administradores), este mensaje está redactado para el usuario final:
// explica por qué dejó de funcionar su cuenta y qué debe hacer.
//
// La entrega funciona aunque la cuenta esté en estado "locked": Zimbra solo
// bloquea la autenticación, el buzón sigue recibiendo correo. El usuario verá
// el aviso cuando el administrador le restablezca la contraseña.
func (n *Notifier) NotifySuspendedUser(ctx context.Context, account string, alert detection.Alert) error {
	if n.cfg.UserNoticeFrom == "" || account == "" {
		return nil
	}

	msg := n.buildUserNotice(account, alert)

	args := []string{"-f", n.cfg.UserNoticeFrom, account}
	cmd := exec.CommandContext(ctx, n.cfg.SendmailBin, args...)
	cmd.Stdin = bytes.NewBufferString(msg)

	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("email: sendmail aviso a usuario %s: %w — %s", account, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (n *Notifier) buildUserNotice(account string, alert detection.Alert) string {
	ts := alert.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}

	var sb strings.Builder

	fmt.Fprintf(&sb, "From: Seguridad del Correo <%s>\r\n", n.cfg.UserNoticeFrom)
	fmt.Fprintf(&sb, "To: %s\r\n", account)
	fmt.Fprintf(&sb, "Subject: =?UTF-8?Q?Alerta_de_seguridad:_su_cuenta_fue_suspendida?=\r\n")
	fmt.Fprintf(&sb, "MIME-Version: 1.0\r\n")
	fmt.Fprintf(&sb, "Content-Type: multipart/alternative; boundary=\"%s\"\r\n", mimeBoundary)
	fmt.Fprintf(&sb, "\r\n")

	fmt.Fprintf(&sb, "--%s\r\n", mimeBoundary)
	fmt.Fprintf(&sb, "Content-Type: text/plain; charset=utf-8\r\n")
	fmt.Fprintf(&sb, "\r\n")
	sb.WriteString(n.buildUserNoticePlain(account, alert, ts))
	fmt.Fprintf(&sb, "\r\n")

	fmt.Fprintf(&sb, "--%s\r\n", mimeBoundary)
	fmt.Fprintf(&sb, "Content-Type: text/html; charset=utf-8\r\n")
	fmt.Fprintf(&sb, "\r\n")
	sb.WriteString(n.buildUserNoticeHTML(account, alert, ts))
	fmt.Fprintf(&sb, "\r\n")

	fmt.Fprintf(&sb, "--%s--\r\n", mimeBoundary)

	return sb.String()
}

func (n *Notifier) buildUserNoticePlain(account string, alert detection.Alert, ts time.Time) string {
	var sb strings.Builder
	sb.WriteString("Alerta de seguridad\n")
	sb.WriteString("===================\n\n")
	fmt.Fprintf(&sb, "Cuenta: %s\n\n", account)
	sb.WriteString("Su cuenta de correo fue SUSPENDIDA automáticamente por el sistema de\n")
	sb.WriteString("seguridad del servidor, al detectarse envíos anómalos realizados con sus\n")
	sb.WriteString("credenciales. Lo más probable es que su contraseña haya sido robada\n")
	sb.WriteString("(phishing o filtración) y esté siendo usada por terceros para enviar spam.\n\n")
	fmt.Fprintf(&sb, "Fecha de la suspensión: %s\n", ts.Format("2006-01-02 15:04:05 -07:00"))
	if alert.IP != "" {
		fmt.Fprintf(&sb, "IP que originó el abuso: %s\n", alert.IP)
	}
	sb.WriteString("\nQué debe hacer:\n")
	fmt.Fprintf(&sb, "  1. Contacte al soporte (%s) para reactivar la cuenta.\n", n.cfg.UserNoticeFrom)
	sb.WriteString("  2. Cambie su contraseña por una NUEVA y única (no reutilice la anterior\n")
	sb.WriteString("     ni una que use en otros servicios).\n")
	sb.WriteString("  3. Revise los equipos donde usaba el correo en busca de malware.\n")
	sb.WriteString("  4. Desconfíe de correos que le pidan su contraseña: ningún soporte\n")
	sb.WriteString("     legítimo se la pedirá.\n\n")
	sb.WriteString("La suspensión protege su identidad y evita que el servidor de su\n")
	sb.WriteString("organización sea catalogado como emisor de spam.\n\n")
	sb.WriteString("— Mensaje automático del sistema de seguridad. No responda a este correo.\n")
	return sb.String()
}

// buildUserNoticeHTML genera el cuerpo HTML con el estilo de las alertas de
// seguridad de Google/Gmail: tarjeta blanca centrada sobre fondo claro, icono,
// titular grande, "pill" con la cuenta afectada, botón azul de acción y pie
// gris. Todo con CSS inline y sin imágenes externas (compatibilidad y para no
// disparar filtros antispam).
func (n *Notifier) buildUserNoticeHTML(account string, alert detection.Alert, ts time.Time) string {
	acc := html.EscapeString(account)
	contact := html.EscapeString(n.cfg.UserNoticeFrom)
	initial := "?"
	if account != "" {
		initial = strings.ToUpper(account[:1])
	}

	var sb strings.Builder
	sb.WriteString(`<html><body style="margin:0;padding:0;background-color:#f6f8fc">`)
	sb.WriteString(`<div style="max-width:480px;margin:0 auto;padding:32px 16px;font-family:'Google Sans',Roboto,Arial,Helvetica,sans-serif">`)

	// Tarjeta principal
	sb.WriteString(`<div style="background:#ffffff;border:1px solid #dadce0;border-radius:8px;padding:48px 40px 36px;text-align:center">`)

	// Icono: escudo rojo de alerta (sin imágenes externas)
	sb.WriteString(`<div style="width:64px;height:64px;margin:0 auto 24px;border-radius:50%;background:#fce8e6;line-height:64px;font-size:32px">&#9888;&#65039;</div>`)

	// Titular y subtítulo
	sb.WriteString(`<div style="font-size:24px;color:#202124;line-height:1.3;margin-bottom:8px">Alerta de seguridad</div>`)
	sb.WriteString(`<div style="font-size:15px;color:#5f6368;margin-bottom:24px">Su cuenta de correo fue suspendida por actividad sospechosa</div>`)

	// Pill con la cuenta afectada (avatar circular + dirección)
	sb.WriteString(`<div style="display:inline-block;border:1px solid #dadce0;border-radius:100px;padding:4px 16px 4px 4px;margin-bottom:24px">`)
	fmt.Fprintf(&sb, `<span style="display:inline-block;width:28px;height:28px;border-radius:50%%;background:#1a73e8;color:#fff;line-height:28px;font-size:14px;text-align:center;vertical-align:middle">%s</span>`, html.EscapeString(initial))
	fmt.Fprintf(&sb, `<span style="font-size:14px;color:#3c4043;vertical-align:middle;padding-left:8px">%s</span>`, acc)
	sb.WriteString(`</div>`)

	// Explicación
	sb.WriteString(`<div style="font-size:14px;color:#5f6368;line-height:1.6;text-align:left;margin-bottom:16px">`)
	sb.WriteString(`El sistema de seguridad detectó envíos anómalos realizados con sus credenciales y suspendió la cuenta ` +
		`para proteger su identidad. Lo más probable es que su contraseña haya sido robada (phishing o filtración) ` +
		`y esté siendo usada por terceros para enviar spam.`)
	sb.WriteString(`</div>`)

	// Datos del evento
	sb.WriteString(`<div style="font-size:13px;color:#5f6368;line-height:1.7;text-align:left;background:#f8f9fa;border-radius:8px;padding:12px 16px;margin-bottom:28px">`)
	fmt.Fprintf(&sb, `<b style="color:#3c4043">Fecha:</b> %s`, ts.Format("2006-01-02 15:04:05 -07:00"))
	if alert.IP != "" {
		fmt.Fprintf(&sb, `<br><b style="color:#3c4043">IP que originó el abuso:</b> %s`, html.EscapeString(alert.IP))
	}
	sb.WriteString(`</div>`)

	// Botón de acción (azul Google)
	fmt.Fprintf(&sb, `<a href="mailto:%s" style="display:inline-block;background:#1a73e8;color:#ffffff;text-decoration:none;font-size:14px;font-weight:500;border-radius:4px;padding:10px 24px;margin-bottom:28px">Contactar al soporte</a>`, contact)

	// Pasos a seguir
	sb.WriteString(`<div style="font-size:14px;color:#5f6368;line-height:1.7;text-align:left;border-top:1px solid #dadce0;padding-top:20px">`)
	sb.WriteString(`<b style="color:#3c4043">Qué debe hacer:</b>`)
	sb.WriteString(`<ol style="margin:8px 0 0;padding-left:20px">`)
	fmt.Fprintf(&sb, `<li>Contacte al soporte (%s) para reactivar la cuenta.</li>`, contact)
	sb.WriteString(`<li>Cambie su contraseña por una <b>nueva y única</b>; no reutilice la anterior ni una que use en otros servicios.</li>`)
	sb.WriteString(`<li>Revise los equipos donde usaba el correo en busca de malware.</li>`)
	sb.WriteString(`<li>Desconfíe de correos que le pidan su contraseña: ningún soporte legítimo se la pedirá.</li>`)
	sb.WriteString(`</ol></div>`)

	sb.WriteString(`</div>`) // fin tarjeta

	// Pie gris fuera de la tarjeta
	sb.WriteString(`<div style="text-align:center;font-size:12px;color:#80868b;line-height:1.6;padding:24px 32px 0">`)
	fmt.Fprintf(&sb, `Recibió este mensaje porque el sistema de seguridad del correo suspendió la cuenta %s. `, acc)
	sb.WriteString(`Este es un mensaje automático; no responda a este correo.`)
	sb.WriteString(`</div>`)

	sb.WriteString(`</div></body></html>`)
	return sb.String()
}
