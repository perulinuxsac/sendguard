package forwarder

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/perulinux/sendguard/internal/detection"
	"github.com/perulinux/sendguard/internal/store"
)

func openMemoryStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func sampleAlert() detection.Alert {
	return detection.Alert{
		Module:    "authfailed",
		Score:     80,
		Severity:  detection.SeveritySuspend,
		Action:    detection.ActionBlockIP,
		Timestamp: time.Now(),
		Server:    "mail.example.com",
		IP:        "1.2.3.4",
		Account:   "user@example.com",
		Domain:    "example.com",
		Reasons:   []string{"5 fallos en 5 minutos"},
	}
}

// ── SaveAlert ─────────────────────────────────────────────────────────────────

func TestSaveAlertSinStore(t *testing.T) {
	f := New(Config{Store: nil})
	f.SaveAlert(sampleAlert()) // no debe panic
}

func TestSaveAlertConStore(t *testing.T) {
	s := openMemoryStore(t)
	f := New(Config{Store: s})

	f.SaveAlert(sampleAlert())

	events, err := s.LoadUnsynced(10)
	if err != nil {
		t.Fatalf("LoadUnsynced: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("esperado 1 evento, got %d", len(events))
	}
	// Verificar que el tipo de evento corresponde a la acción
	if string(events[0].Type) != string(detection.ActionBlockIP) {
		t.Errorf("tipo: got %q, want %q", events[0].Type, detection.ActionBlockIP)
	}
	// Verificar que los metadatos se serializaron en raw
	var meta alertMeta
	if err := json.Unmarshal([]byte(events[0].Raw), &meta); err != nil {
		t.Fatalf("raw no es JSON válido: %v", err)
	}
	if meta.Module != "authfailed" {
		t.Errorf("meta.module: got %q, want authfailed", meta.Module)
	}
	if meta.Score != 80 {
		t.Errorf("meta.score: got %d, want 80", meta.Score)
	}
}

func TestSaveAlertMapeoIP(t *testing.T) {
	s := openMemoryStore(t)
	f := New(Config{Store: s})

	alert := sampleAlert()
	f.SaveAlert(alert)

	events, _ := s.LoadUnsynced(10)
	if events[0].IP != "1.2.3.4" {
		t.Errorf("IP: got %q, want 1.2.3.4", events[0].IP)
	}
	if events[0].Account != "user@example.com" {
		t.Errorf("Account: got %q", events[0].Account)
	}
}

func TestSaveAlertMultiples(t *testing.T) {
	s := openMemoryStore(t)
	f := New(Config{Store: s})

	for i := 0; i < 5; i++ {
		f.SaveAlert(sampleAlert())
	}

	events, _ := s.LoadUnsynced(10)
	if len(events) != 5 {
		t.Errorf("esperado 5 eventos, got %d", len(events))
	}
}

// ── Run ───────────────────────────────────────────────────────────────────────

func TestRunSinStore(t *testing.T) {
	f := New(Config{Store: nil})
	done := make(chan struct{})
	go func() {
		f.Run(context.Background())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Error("Run sin store debe retornar inmediatamente")
	}
}

func TestRunExitaConCtxCancelado(t *testing.T) {
	s := openMemoryStore(t)
	f := New(Config{Store: s, SyncInterval: time.Hour})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		f.Run(ctx)
		close(done)
	}()

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Error("Run no terminó tras cancelar ctx")
	}
}

// ── syncBatch ─────────────────────────────────────────────────────────────────

func TestSyncBatchSinController(t *testing.T) {
	s := openMemoryStore(t)
	f := New(Config{Store: s, ControllerURL: ""})

	f.SaveAlert(sampleAlert())
	f.syncBatch(context.Background()) // no debe intentar envío

	// El evento debe seguir como no sincronizado
	events, _ := s.LoadUnsynced(10)
	if len(events) != 1 {
		t.Errorf("sin controller: evento debe seguir pendiente, got %d sincronizados", 1-len(events))
	}
}

func TestSyncBatchConControllerOK(t *testing.T) {
	received := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/events" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		received++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := openMemoryStore(t)
	f := New(Config{Store: s, ControllerURL: srv.URL, BatchSize: 10})

	f.SaveAlert(sampleAlert())
	f.SaveAlert(sampleAlert())
	f.syncBatch(context.Background())

	if received != 1 {
		t.Errorf("Controller debe recibir 1 request, got %d", received)
	}
	// Tras sync exitoso, no debe haber pendientes
	events, _ := s.LoadUnsynced(10)
	if len(events) != 0 {
		t.Errorf("tras sync: esperado 0 pendientes, got %d", len(events))
	}
}

func TestSyncBatchConControllerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	s := openMemoryStore(t)
	f := New(Config{Store: s, ControllerURL: srv.URL})

	f.SaveAlert(sampleAlert())
	f.syncBatch(context.Background())

	// Si el Controller falla, los eventos deben seguir pendientes
	events, _ := s.LoadUnsynced(10)
	if len(events) != 1 {
		t.Errorf("tras error del controller: evento debe seguir pendiente, got %d", len(events))
	}
}

func TestSyncBatchControllerConAPIKey(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := openMemoryStore(t)
	f := New(Config{Store: s, ControllerURL: srv.URL, APIKey: "secret-token"})

	f.SaveAlert(sampleAlert())
	f.syncBatch(context.Background())

	if gotAuth != "Bearer secret-token" {
		t.Errorf("Authorization: got %q, want Bearer secret-token", gotAuth)
	}
}

func TestSyncBatchSinEventos(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("no debe llamar al Controller si no hay eventos pendientes")
	}))
	defer srv.Close()

	s := openMemoryStore(t)
	f := New(Config{Store: s, ControllerURL: srv.URL})
	f.syncBatch(context.Background()) // no debe llamar al servidor
}

func TestSyncBatchLoadUnsyncedError(t *testing.T) {
	s, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	s.Close() // cierra la DB para forzar error en LoadUnsynced

	f := New(Config{Store: s, ControllerURL: "http://example.com"})
	f.syncBatch(context.Background()) // slog.Warn + return, no panic
}

func TestSyncBatchNetworkError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close() // cerrar el servidor para que las conexiones sean rechazadas

	s := openMemoryStore(t)
	f := New(Config{Store: s, ControllerURL: url, BatchSize: 10})

	f.SaveAlert(sampleAlert())
	f.syncBatch(context.Background()) // httpClient.Do falla → warn + return

	events, _ := s.LoadUnsynced(10)
	if len(events) != 1 {
		t.Errorf("tras error de red: esperado 1 pendiente, got %d", len(events))
	}
}

func TestSyncBatchURLInvalida(t *testing.T) {
	s := openMemoryStore(t)
	f := New(Config{Store: s, ControllerURL: "://invalid"})

	f.SaveAlert(sampleAlert())
	f.syncBatch(context.Background()) // http.NewRequestWithContext falla → return silencioso

	events, _ := s.LoadUnsynced(10)
	if len(events) != 1 {
		t.Errorf("tras URL inválida: esperado 1 pendiente, got %d", len(events))
	}
}

func TestRunPruneTicker(t *testing.T) {
	s := openMemoryStore(t)
	f := New(Config{
		Store:         s,
		SyncInterval:  time.Hour,             // no disparar sync
		pruneInterval: 10 * time.Millisecond, // disparar prune rápidamente
	})

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() {
		f.Run(ctx)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Error("Run no terminó tras cancelar ctx")
	}
}
