// Package telegram implementa notificaciones vía Telegram Bot API.
// Cada alerta genera un mensaje con formato estructurado y emojis indicadores
// de severidad para facilitar la lectura en móvil.
package telegram

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/perulinux/sendguard/internal/detection"
)

// Config agrupa los parámetros necesarios para usar la Bot API de Telegram.
type Config struct {
	Token  string // token del bot (formato: 123456:ABC-DEF...)
	ChatID string // ID del chat/grupo/canal destino
}

// Notifier envía alertas de SendGuard a un chat de Telegram.
type Notifier struct {
	cfg    Config
	client *http.Client
	apiURL string // base de la API; se puede sobrescribir en tests
}

// New crea un Notifier con timeout razonable para no bloquear el pipeline.
func New(cfg Config) *Notifier {
	return &Notifier{
		cfg:    cfg,
		client: &http.Client{Timeout: 10 * time.Second},
		apiURL: "https://api.telegram.org",
	}
}

// NewForTest crea un Notifier apuntando a una URL base distinta.
// Solo debe usarse en tests.
func NewForTest(cfg Config, apiURL string) *Notifier {
	n := New(cfg)
	n.apiURL = apiURL
	return n
}

// Notify formatea la alerta y la envía al chat configurado.
func (n *Notifier) Notify(ctx context.Context, alert detection.Alert) error {
	text := formatAlert(alert)

	body, err := json.Marshal(map[string]string{
		"chat_id":    n.cfg.ChatID,
		"text":       text,
		"parse_mode": "HTML",
	})
	if err != nil {
		return fmt.Errorf("telegram: marshal payload: %w", err)
	}

	url := fmt.Sprintf("%s/bot%s/sendMessage", n.apiURL, n.cfg.Token)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("telegram: crear request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := n.client.Do(req)
	if err != nil {
		return fmt.Errorf("telegram: enviar mensaje: %w", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("telegram: HTTP %d: %s", resp.StatusCode, raw)
	}

	var result struct {
		OK          bool   `json:"ok"`
		Description string `json:"description"`
	}
	if err := json.Unmarshal(raw, &result); err == nil && !result.OK {
		return fmt.Errorf("telegram: API error: %s", result.Description)
	}

	slog.Debug("telegram: notificación enviada", "chat_id", n.cfg.ChatID, "module", alert.Module)
	return nil
}

// severityEmoji devuelve el emoji y etiqueta de texto según la severidad.
func severityEmoji(s detection.Severity) string {
	switch s {
	case detection.SeveritySuspend:
		return "🔴 CRÍTICO"
	case detection.SeverityRateLimit:
		return "🟠 ALTO"
	case detection.SeverityWarn:
		return "🟡 MEDIO"
	default:
		return "🔵 INFO"
	}
}

// actionLabel traduce la acción a texto legible. Para ActionNotifyOnly usa el
// módulo para dar contexto específico en lugar de un genérico "Notificación".
func actionLabel(a detection.Action, module string) string {
	switch a {
	case detection.ActionBlockIP:
		return "IP bloqueada"
	case detection.ActionSuspendAcct:
		return "Cuenta suspendida"
	case detection.ActionRateLimit:
		return "Rate-limit aplicado"
	case detection.ActionNotifyOnly:
		return moduleNotifyLabel(module)
	default:
		return "Notificación"
	}
}

// moduleNotifyLabel devuelve una etiqueta contextual según el módulo que emite
// ActionNotifyOnly, para que el administrador identifique el tipo de problema
// sin leer el cuerpo del mensaje.
func moduleNotifyLabel(module string) string {
	switch module {
	case "queue_monitor":
		return "Alerta de reputación"
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

// formatAlert construye el texto HTML del mensaje de Telegram.
func formatAlert(alert detection.Alert) string {
	var sb strings.Builder

	// Cabecera: escudo + severidad en la primera línea para lectura rápida en móvil
	fmt.Fprintf(&sb, "🛡 <b>SendGuard</b>  %s\n", severityEmoji(alert.Severity))
	fmt.Fprintf(&sb, "<b>%s</b>  ·  <i>%s</i>\n", actionLabel(alert.Action, alert.Module), alert.Module)
	sb.WriteString("─────────────────────\n")

	if alert.Server != "" {
		fmt.Fprintf(&sb, "🖥 Servidor: <code>%s</code>\n", alert.Server)
	}
	if alert.IP != "" {
		fmt.Fprintf(&sb, "🌐 IP: <code>%s</code>\n", alert.IP)
	}
	if alert.Account != "" {
		fmt.Fprintf(&sb, "👤 Cuenta: <code>%s</code>\n", alert.Account)
	}
	if alert.Domain != "" {
		fmt.Fprintf(&sb, "📧 Dominio: <code>%s</code>\n", alert.Domain)
	}
	fmt.Fprintf(&sb, "📊 Score: <b>%d</b>/100\n", alert.Score)

	if len(alert.Reasons) > 0 {
		fmt.Fprintf(&sb, "\n📋 <i>%s</i>", strings.Join(alert.Reasons, "; "))
	}

	ts := alert.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}
	fmt.Fprintf(&sb, "\n\n🕐 %s", ts.Format("2006-01-02 15:04:05"))

	return sb.String()
}
