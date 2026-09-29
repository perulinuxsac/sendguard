// Package present decide cómo se presenta una alerta al administrador: título,
// tono, qué hacer y cómo revertir. Lo comparten Telegram, email y webhook para
// que los tres canales digan exactamente lo mismo.
//
// El título sale del resultado real de la contención (Alert.Outcome), no de la
// acción que pidió el módulo: un suspend_account puede haberse ejecutado,
// omitido por país permitido, estar ya aplicado o haber fallado, y cada caso
// exige una reacción distinta del administrador.
package present

import (
	"fmt"
	"strings"

	"github.com/perulinux/sendguard/internal/detection"
)

// Tone es el nivel visual de la alerta (color en email, orden de lectura).
type Tone int

const (
	ToneInfo     Tone = iota // informativa
	ToneMuted                // repetición de algo ya contenido
	ToneWarning              // requiere revisión manual
	ToneHigh                 // contención aplicada (IP)
	ToneCritical             // contención aplicada (cuenta comprometida)
	ToneFailed               // la contención falló: hay que actuar ya
)

// View es la presentación de una alerta, independiente del canal.
type View struct {
	Icon   string // emoji del título
	Title  string // "Cuenta suspendida", "FALLÓ la suspensión de la cuenta"…
	Target string // cuenta o IP afectada (lo más importante después del título)
	Tone   Tone
	What   string // descripción legible del módulo que detectó
	Next   string // qué debe hacer el administrador ("" si nada)
	Revert string // comando para revertir la contención ("" si no aplica)
}

// Build arma la presentación de la alerta.
func Build(a detection.Alert) View {
	v := View{What: ModuleName(a.Module)}
	outcome := a.Outcome

	switch a.Action {
	case detection.ActionSuspendAcct:
		v.Target = a.Account
		switch outcome {
		case detection.OutcomeFailed:
			v.Icon, v.Title, v.Tone = "❌", "FALLÓ la suspensión de la cuenta", ToneFailed
			v.Next = "La cuenta sigue ACTIVA. Suspéndela a mano: zmprov ma " + a.Account + " zimbraAccountStatus locked"
		case detection.OutcomeSkipped:
			v.Icon, v.Title, v.Tone = "⚠️", "Suspensión omitida — revisar", ToneWarning
			v.Next = "No se suspendió porque la IP es de un país permitido. Verifica con el usuario si el acceso es suyo."
		case detection.OutcomeAlready:
			v.Icon, v.Title, v.Tone = "🔒", "Cuenta ya suspendida — nueva actividad", ToneMuted
			v.Revert = "sendguard-ctl unsuspend " + a.Account
		default: // applied (o alerta sin evaluar)
			v.Icon, v.Title, v.Tone = "🔒", "Cuenta suspendida", ToneCritical
			v.Next = "Cambia la contraseña de la cuenta antes de rehabilitarla."
			v.Revert = "sendguard-ctl unsuspend " + a.Account
		}

	case detection.ActionBlockIP:
		v.Target = a.IP
		switch outcome {
		case detection.OutcomeFailed:
			v.Icon, v.Title, v.Tone = "❌", "FALLÓ el bloqueo de IP", ToneFailed
			v.Next = "La IP sigue con acceso. Revisa el firewall y bloquéala a mano: sendguard-ctl block " + a.IP
		case detection.OutcomeSkipped:
			v.Icon, v.Title, v.Tone = "⚠️", "Bloqueo omitido — revisar", ToneWarning
			v.Next = "No se bloqueó (país permitido o red privada). Verifica si la actividad es legítima."
		case detection.OutcomeAlready:
			v.Icon, v.Title, v.Tone = "🚫", "IP ya bloqueada", ToneMuted
			v.Revert = "sendguard-ctl unblock " + a.IP
		default:
			v.Icon, v.Title, v.Tone = "🚫", "IP bloqueada", ToneHigh
			v.Revert = "sendguard-ctl unblock " + a.IP
		}

	case detection.ActionUnsuspendAcct:
		v.Icon, v.Title, v.Tone, v.Target = "🔓", "Cuenta rehabilitada", ToneInfo, a.Account
	case detection.ActionUnblockIP:
		v.Icon, v.Title, v.Tone, v.Target = "✅", "IP desbloqueada", ToneInfo, a.IP

	default: // notify_only: el módulo da el contexto
		v.Icon, v.Title = notifyIcon(a.Module), notifyTitle(a.Module)
		v.Tone = ToneInfo
		if a.Severity >= detection.SeverityHigh {
			v.Tone = ToneWarning
		}
		v.Target = firstNonEmpty(a.Account, a.IP, a.Domain)
		v.Next = "Solo aviso: el agente no ejecutó ninguna acción. Revisa si hace falta intervenir."
	}
	if v.Target == "" {
		v.Target = firstNonEmpty(a.Account, a.IP, a.Domain)
	}
	return v
}

// ModuleName describe en lenguaje llano qué detectó cada módulo.
func ModuleName(module string) string {
	switch module {
	case "auth_failed":
		return "Fuerza bruta contra el login desde una IP"
	case "number_messages":
		return "Volumen anómalo de correo hacia dominios externos"
	case "sasl_connections":
		return "Cuenta usada desde demasiadas conexiones o IPs"
	case "dist_brute_force":
		return "Fuerza bruta distribuida contra una cuenta"
	case "impossible_traveler":
		return "Viaje imposible: logins desde países distintos en poco tiempo"
	case "queue_monitor":
		return "Un dominio destino está rechazando el correo del servidor"
	case "domain_discovery":
		return "Barrido de cuentas de muchas organizaciones desde una IP"
	case "bounce_rate":
		return "Rebotes masivos: la cuenta envía a direcciones inválidas"
	case "rcpt_flood":
		return "Envío masivo a muchos destinatarios"
	case "password_spray":
		return "Password spraying: una IP probando muchas cuentas"
	case "account_takeover":
		return "Robo de cuenta: fuerza bruta seguida de acceso"
	case "manual":
		return "Acción manual del administrador"
	case "":
		return ""
	default:
		return module
	}
}

// notifyTitle titula las alertas notify_only según el módulo.
func notifyTitle(module string) string {
	switch module {
	case "queue_monitor":
		return "Problema de reputación de envío"
	case "dist_brute_force":
		return "Fuerza bruta distribuida"
	case "domain_discovery":
		return "Reconocimiento de dominios"
	case "bounce_rate":
		return "Tasa de rebote alta"
	case "account_takeover":
		return "Posible robo de cuenta"
	default:
		return "Actividad sospechosa"
	}
}

func notifyIcon(module string) string {
	switch module {
	case "queue_monitor", "bounce_rate":
		return "📨"
	case "dist_brute_force", "account_takeover":
		return "⚠️"
	default:
		return "🔔"
	}
}

// SeverityLabel traduce la severidad a texto.
func SeverityLabel(s detection.Severity) string {
	switch s {
	case detection.SeveritySuspend:
		return "CRÍTICO"
	case detection.SeverityHigh:
		return "ALTO"
	case detection.SeverityWarn:
		return "MEDIO"
	default:
		return "INFO"
	}
}

// SeverityDot es el indicador de color de la severidad para texto plano/Telegram.
func SeverityDot(s detection.Severity) string {
	switch s {
	case detection.SeveritySuspend:
		return "🔴"
	case detection.SeverityHigh:
		return "🟠"
	case detection.SeverityWarn:
		return "🟡"
	default:
		return "🔵"
	}
}

// EffectIcon es el marcador de cada acción ejecutada por el agente.
func EffectIcon(o detection.Outcome) string {
	switch o {
	case detection.OutcomeApplied:
		return "✅"
	case detection.OutcomeFailed:
		return "❌"
	case detection.OutcomeAlready:
		return "↩️"
	default:
		return "⚠️"
	}
}

// Flag convierte un código ISO 3166-1 alpha-2 en su bandera emoji ("PE" → 🇵🇪).
// Devuelve "" si el código no es de dos letras.
func Flag(country string) string {
	c := strings.ToUpper(strings.TrimSpace(country))
	if len(c) != 2 || c[0] < 'A' || c[0] > 'Z' || c[1] < 'A' || c[1] > 'Z' {
		return ""
	}
	return string([]rune{rune(c[0]) - 'A' + 0x1F1E6, rune(c[1]) - 'A' + 0x1F1E6})
}

// Country formatea el país con su bandera: "🇵🇪 PE".
func Country(country string) string {
	if country == "" {
		return ""
	}
	if f := Flag(country); f != "" {
		return f + " " + strings.ToUpper(country)
	}
	return country
}

// Subject es el asunto del correo / resumen de una línea de la alerta.
func Subject(a detection.Alert) string {
	v := Build(a)
	s := fmt.Sprintf("[SendGuard] %s %s", v.Icon, v.Title)
	if v.Target != "" {
		s += ": " + v.Target
	}
	if a.Server != "" {
		s += " (" + a.Server + ")"
	}
	return s
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
