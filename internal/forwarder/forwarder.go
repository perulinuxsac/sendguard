// Package forwarder implementa el patrón StoreAndForward para el agente SendGuard.
//
// Las alertas se persisten primero en SQLite local (Store) y luego se reenvían
// al Controller central en lotes cuando hay conectividad. Si el Controller no
// está disponible o no está configurado, los eventos quedan en SQLite hasta que
// la conectividad se restaure o sean podados por antigüedad.
//
// Modo standalone (ControllerURL vacío): solo persiste, nunca envía.
// Modo conectado (ControllerURL configurado): persiste + envía en lotes.
package forwarder

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/perulinux/sendguard/internal/detection"
	"github.com/perulinux/sendguard/internal/event"
	"github.com/perulinux/sendguard/internal/store"
)

// Config agrupa los parámetros del Forwarder.
type Config struct {
	Store         *store.Store
	ControllerURL string        // vacío = solo persiste, no envía
	APIKey        string        // Bearer token para el Controller
	SyncInterval  time.Duration // 0 = 30s
	BatchSize     int           // 0 = 100
	pruneInterval time.Duration // 0 = time.Hour; override in tests
}

// Forwarder persiste alertas en SQLite local y las reenvía al Controller
// cuando hay conectividad. Es thread-safe.
type Forwarder struct {
	cfg        Config
	httpClient *http.Client
}

// New crea un Forwarder con la configuración dada.
func New(cfg Config) *Forwarder {
	if cfg.SyncInterval == 0 {
		cfg.SyncInterval = 30 * time.Second
	}
	if cfg.BatchSize == 0 {
		cfg.BatchSize = 100
	}
	return &Forwarder{
		cfg:        cfg,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

// alertMeta contiene los metadatos de una alerta serializados en el campo raw de SQLite.
type alertMeta struct {
	Module   string   `json:"module"`
	Score    int      `json:"score"`
	Severity int      `json:"severity"`
	Reasons  []string `json:"reasons"`
}

// ControllerAlertPayload es la estructura JSON que el agente envía al Controller.
// Todos los campos del alert se exponen como campos de primer nivel para que
// el Controller pueda consumirlos sin doble-parseo.
type ControllerAlertPayload struct {
	ID        int64     `json:"id"`
	Type      string    `json:"type"`              // acción: block_ip, suspend_account, etc.
	Module    string    `json:"module"`
	Score     int       `json:"score"`
	Severity  int       `json:"severity"`
	Timestamp time.Time `json:"timestamp"`
	Server    string    `json:"server"`
	IP        string    `json:"ip,omitempty"`
	Account   string    `json:"account,omitempty"`
	Domain    string    `json:"domain,omitempty"`
	Country   string    `json:"country,omitempty"`
	Reasons   []string  `json:"reasons"`
}

// SaveAlert persiste una alerta en SQLite para su posterior envío al Controller.
// Mapea los campos de detection.Alert a las columnas de pending_events.
// Es un no-op si Store es nil.
func (f *Forwarder) SaveAlert(a detection.Alert) {
	if f.cfg.Store == nil {
		return
	}
	meta, _ := json.Marshal(alertMeta{
		Module:   a.Module,
		Score:    a.Score,
		Severity: int(a.Severity),
		Reasons:  a.Reasons,
	})
	ev := event.Event{
		Type:      event.Type(string(a.Action)),
		Timestamp: a.Timestamp,
		Server:    a.Server,
		IP:        a.IP,
		Account:   a.Account,
		Domain:    a.Domain,
		Country:   a.Country,
		Raw:       string(meta),
	}
	if err := f.cfg.Store.SaveEvent(ev); err != nil {
		slog.Warn("forwarder: no se pudo persistir alerta", "error", err)
	}
}

// Run inicia el loop de sincronización y poda periódica.
// Bloquea hasta que ctx sea cancelado.
// Es un no-op inmediato si Store es nil.
func (f *Forwarder) Run(ctx context.Context) {
	if f.cfg.Store == nil {
		return
	}

	syncTicker := time.NewTicker(f.cfg.SyncInterval)
	defer syncTicker.Stop()

	pruneInterval := f.cfg.pruneInterval
	if pruneInterval == 0 {
		pruneInterval = time.Hour
	}
	pruneTicker := time.NewTicker(pruneInterval)
	defer pruneTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-syncTicker.C:
			if f.cfg.ControllerURL != "" {
				f.syncBatch(ctx)
			}
		case <-pruneTicker.C:
			n, err := f.cfg.Store.PruneSyncedEvents(24 * time.Hour)
			if err != nil {
				slog.Warn("forwarder: error al podar eventos sincronizados", "error", err)
			} else if n > 0 {
				slog.Info("forwarder: eventos sincronizados podados", "count", n)
			}
		}
	}
}

// syncBatch carga un lote de eventos no sincronizados y los envía al Controller.
// Solo marca como sincronizados si el Controller responde con 200 o 204.
func (f *Forwarder) syncBatch(ctx context.Context) {
	events, err := f.cfg.Store.LoadUnsynced(f.cfg.BatchSize)
	if err != nil {
		slog.Warn("forwarder: error al cargar eventos pendientes", "error", err)
		return
	}
	if len(events) == 0 {
		return
	}

	// Convertir a ControllerAlertPayload: campos de primer nivel, sin doble-parseo
	// en el lado del Controller. El campo raw (alertMeta) se deserializa aquí.
	payloads := make([]ControllerAlertPayload, 0, len(events))
	for _, pe := range events {
		p := ControllerAlertPayload{
			ID:        pe.ID,
			Type:      string(pe.Event.Type),
			Timestamp: pe.Event.Timestamp,
			Server:    pe.Event.Server,
			IP:        pe.Event.IP,
			Account:   pe.Event.Account,
			Domain:    pe.Event.Domain,
			Country:   pe.Event.Country,
		}
		var meta alertMeta
		if err := json.Unmarshal([]byte(pe.Event.Raw), &meta); err == nil {
			p.Module = meta.Module
			p.Score = meta.Score
			p.Severity = meta.Severity
			p.Reasons = meta.Reasons
		}
		payloads = append(payloads, p)
	}

	body, err := json.Marshal(payloads)
	if err != nil {
		slog.Warn("forwarder: error al serializar eventos", "error", err)
		return
	}

	url := f.cfg.ControllerURL + "/api/v1/events"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if f.cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+f.cfg.APIKey)
	}

	resp, err := f.httpClient.Do(req)
	if err != nil {
		slog.Warn("forwarder: Controller no disponible, reintentando en el próximo ciclo",
			"pendientes", len(events), "error", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		slog.Warn("forwarder: Controller rechazó el lote",
			"status", resp.StatusCode, "pendientes", len(events))
		return
	}

	ids := make([]int64, len(events))
	for i, e := range events {
		ids[i] = e.ID
	}
	if err := f.cfg.Store.MarkSynced(ids); err != nil {
		slog.Warn("forwarder: error al marcar eventos como sincronizados", "error", err)
		return
	}
	slog.Info("forwarder: lote sincronizado con Controller",
		"count", len(ids), "url", f.cfg.ControllerURL)
}
