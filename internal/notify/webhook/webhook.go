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
	"strings"
	"time"

	"github.com/perulinux/sendguard/internal/detection"
	"github.com/perulinux/sendguard/internal/notify/present"
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
	Country   string    `json:"country,omitempty"`

	// Resultado real de la contención (ver detection.Outcome): applied |
	// skipped | already | failed; vacío en alertas notify_only.
	Outcome       string   `json:"outcome,omitempty"`
	OutcomeDetail string   `json:"outcome_detail,omitempty"`
	Effects       []effect `json:"effects,omitempty"`
	Title         string   `json:"title"`

	// Campo extra para facilitar Slack Block Kit / Teams Adaptive Cards.
	Text string `json:"text"`
}

// effect es una acción ejecutada por el agente para la alerta.
type effect struct {
	Outcome string `json:"outcome"`
	Text    string `json:"text"`
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
		Country:   alert.Country,
		Outcome:   string(alert.Outcome),
		Title:     present.Build(alert).Title,
		Text:      formatText(alert),
	}
	p.OutcomeDetail = alert.OutcomeDetail
	for _, e := range alert.Effects {
		p.Effects = append(p.Effects, effect{Outcome: string(e.Outcome), Text: e.Text})
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
	// Una línea legible en Slack/Teams: resultado real + objetivo + acciones.
	text := present.Subject(a)
	// La otra identidad como contexto: la cuenta en un bloqueo de IP, la IP en
	// una suspensión (el título solo lleva el objetivo principal).
	if target := present.Build(a).Target; a.Account != "" && a.Account != target {
		text += " · cuenta " + a.Account
	} else if a.IP != "" && a.IP != target {
		text += " · IP " + a.IP
	}
	var acts []string
	for _, e := range a.Effects {
		acts = append(acts, present.EffectIcon(e.Outcome)+" "+e.Text)
	}
	if len(acts) > 0 {
		text += " — " + strings.Join(acts, "; ")
	}
	return fmt.Sprintf("%s [%s %d/100]", text, present.SeverityLabel(a.Severity), a.Score)
}
