// Package webhook implementa un Notifier que envía alertas via HTTP POST JSON.
// Compatible con Slack incoming webhooks, Teams, Mattermost, n8n, y cualquier
// endpoint que acepte JSON arbitrario.
package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/perulinux/sendguard/internal/detection"
)

// Config configura el notificador webhook.
type Config struct {
	URL     string // URL del endpoint destino (requerido)
	Timeout int    // timeout en segundos (0 usa el default de 10s)
}

// Notifier envía alertas a un endpoint HTTP genérico.
type Notifier struct {
	cfg    Config
	client *http.Client
}

// New crea un Notifier con la configuración dada.
func New(cfg Config) *Notifier {
	timeout := time.Duration(cfg.Timeout) * time.Second
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	return &Notifier{
		cfg:    cfg,
		client: &http.Client{Timeout: timeout},
	}
}

// NewForTest crea un Notifier apuntando a una URL de prueba (httptest.Server).
func NewForTest(cfg Config, url string) *Notifier {
	n := New(cfg)
	n.cfg.URL = url
	return n
}

// payload es el cuerpo JSON enviado al webhook.
// Incluye todos los campos relevantes de la alerta más contexto de SendGuard.
type payload struct {
	Source    string    `json:"source"`
	Timestamp time.Time `json:"timestamp"`
	Module    string    `json:"module"`
	Action    string    `json:"action"`
	Severity  int       `json:"severity"`
	Score     int       `json:"score"`
	IP        string    `json:"ip,omitempty"`
	Account   string    `json:"account,omitempty"`
	Domain    string    `json:"domain,omitempty"`
	Server    string    `json:"server,omitempty"`
	Reasons   []string  `json:"reasons,omitempty"`
	// Campo extra para facilitar Slack Block Kit / Teams Adaptive Cards.
	Text string `json:"text"`
}

// Notify serializa la alerta y hace POST al endpoint configurado.
func (n *Notifier) Notify(ctx context.Context, alert detection.Alert) error {
	p := payload{
		Source:    "sendguard",
		Timestamp: alert.Timestamp,
		Module:    alert.Module,
		Action:    string(alert.Action),
		Severity:  int(alert.Severity),
		Score:     alert.Score,
		IP:        alert.IP,
		Account:   alert.Account,
		Domain:    alert.Domain,
		Server:    alert.Server,
		Reasons:   alert.Reasons,
		Text:      formatText(alert),
	}

	body, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("webhook: marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.cfg.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("webhook: crear request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := n.client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook: POST a %s: %w", n.cfg.URL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook: respuesta %d de %s", resp.StatusCode, n.cfg.URL)
	}
	return nil
}

// formatText genera una línea de texto legible para herramientas como Slack
// que muestran el campo "text" como mensaje principal.
func formatText(a detection.Alert) string {
	labels := []string{"INFO", "WARN", "RATE-LIMIT", "CRÍTICO"}
	idx := int(a.Severity)
	if idx >= len(labels) {
		idx = len(labels) - 1
	}
	severity := labels[idx]

	switch {
	case a.IP != "" && a.Account != "":
		return fmt.Sprintf("[SendGuard][%s] %s — IP: %s Cuenta: %s (score %d)", severity, a.Module, a.IP, a.Account, a.Score)
	case a.IP != "":
		return fmt.Sprintf("[SendGuard][%s] %s — IP: %s (score %d)", severity, a.Module, a.IP, a.Score)
	case a.Account != "":
		return fmt.Sprintf("[SendGuard][%s] %s — Cuenta: %s (score %d)", severity, a.Module, a.Account, a.Score)
	default:
		return fmt.Sprintf("[SendGuard][%s] %s (score %d)", severity, a.Module, a.Score)
	}
}
