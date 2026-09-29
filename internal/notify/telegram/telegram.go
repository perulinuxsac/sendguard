// Package telegram implementa notificaciones vía Telegram Bot API.
// Cada alerta genera un mensaje estructurado (ver internal/notify/present) que
// se lee de un vistazo en el móvil: resultado real, qué pasó, qué hizo el
// agente y cómo revertirlo.
package telegram

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/perulinux/sendguard/internal/detection"
	"github.com/perulinux/sendguard/internal/notify/present"
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

// maxReasons limita las líneas de detalle para que el mensaje se lea en el móvil.
const maxReasons = 4

// formatAlert construye el texto HTML del mensaje de Telegram. Estructura:
// título según el resultado real → qué pasó → qué hizo el agente → origen →
// qué hacer / cómo revertir.
//
// Los campos que provienen de los logs (cuenta, servidor, razones…) se escapan:
// con parse_mode=HTML un "<" sin escapar hace que la Bot API rechace el mensaje
// completo ("can't parse entities") y la notificación se perdería.
func formatAlert(alert detection.Alert) string {
	v := present.Build(alert)
	esc := html.EscapeString
	var sb strings.Builder

	// Título y objetivo: lo que el administrador necesita ver en la vista previa.
	fmt.Fprintf(&sb, "%s <b>%s</b>\n", v.Icon, esc(v.Title))
	if v.Target != "" {
		fmt.Fprintf(&sb, "<code>%s</code>\n", esc(v.Target))
	}

	// Qué pasó
	fmt.Fprintf(&sb, "\n<b>Qué pasó</b> · %s %s %d/100\n",
		present.SeverityDot(alert.Severity), present.SeverityLabel(alert.Severity), alert.Score)
	if v.What != "" {
		fmt.Fprintf(&sb, "%s\n", esc(v.What))
	}
	for i, r := range alert.Reasons {
		if i == maxReasons {
			fmt.Fprintf(&sb, "<i>… y %d más</i>\n", len(alert.Reasons)-maxReasons)
			break
		}
		fmt.Fprintf(&sb, "• <i>%s</i>\n", esc(r))
	}

	// Qué hizo el agente
	if len(alert.Effects) > 0 {
		sb.WriteString("\n<b>Acciones del agente</b>\n")
		for _, e := range alert.Effects {
			fmt.Fprintf(&sb, "%s %s\n", present.EffectIcon(e.Outcome), esc(e.Text))
		}
	}

	// Origen
	sb.WriteString("\n<b>Origen</b>\n")
	if alert.IP != "" {
		fmt.Fprintf(&sb, "🌐 <code>%s</code>", esc(alert.IP))
		if alert.Country != "" {
			fmt.Fprintf(&sb, " %s", esc(present.Country(alert.Country)))
		}
		sb.WriteString("\n")
	}
	if alert.Account != "" && alert.Account != v.Target {
		fmt.Fprintf(&sb, "👤 <code>%s</code>\n", esc(alert.Account))
	}
	if alert.Domain != "" && alert.Account == "" {
		fmt.Fprintf(&sb, "📧 %s\n", esc(alert.Domain))
	}
	ts := alert.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}
	var meta []string
	if alert.Server != "" {
		meta = append(meta, "🖥 "+esc(alert.Server))
	}
	meta = append(meta, "🕐 "+ts.Format("2006-01-02 15:04:05 -07:00"))
	sb.WriteString(strings.Join(meta, " · "))
	fmt.Fprintf(&sb, "\n<i>módulo %s</i>\n", esc(alert.Module))

	// Qué hacer
	if v.Next != "" {
		fmt.Fprintf(&sb, "\n👉 %s\n", esc(v.Next))
	}
	if v.Revert != "" {
		fmt.Fprintf(&sb, "↩️ Revertir: <code>%s</code>\n", esc(v.Revert))
	}

	return strings.TrimRight(sb.String(), "\n")
}
