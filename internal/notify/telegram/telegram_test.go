package telegram_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/perulinux/sendguard/internal/detection"
	"github.com/perulinux/sendguard/internal/notify/telegram"
)

// okServer devuelve un servidor que responde 200 OK con un JSON mínimo válido
// de la API de Telegram y captura el último request recibido.
func okServer(t *testing.T) (*httptest.Server, *http.Request, *[]byte) {
	t.Helper()
	var lastReq *http.Request
	var lastBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastReq = r
		lastBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(srv.Close)
	return srv, lastReq, &lastBody
}

func sampleAlert() detection.Alert {
	return detection.Alert{
		Module:    "auth_failed",
		Score:     85,
		Severity:  detection.SeveritySuspend,
		Action:    detection.ActionSuspendAcct,
		Timestamp: time.Date(2024, 5, 11, 10, 30, 0, 0, time.UTC),
		Server:    "mail01",
		IP:        "1.2.3.4",
		Account:   "user@example.com",
		Reasons:   []string{"10 fallos en 120s"},
	}
}

func TestNotifyEnviaPost(t *testing.T) {
	srv, _, bodyPtr := okServer(t)
	cfg := telegram.Config{Token: "test-token", ChatID: "12345"}
	n := telegram.NewForTest(cfg, srv.URL)

	if err := n.Notify(context.Background(), sampleAlert()); err != nil {
		t.Fatalf("Notify: %v", err)
	}

	body := *bodyPtr
	if len(body) == 0 {
		t.Fatal("el servidor no recibió body")
	}

	var payload map[string]string
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("body no es JSON válido: %v", err)
	}
	if payload["chat_id"] != "12345" {
		t.Errorf("chat_id: got %q, want %q", payload["chat_id"], "12345")
	}
	if payload["parse_mode"] != "HTML" {
		t.Errorf("parse_mode: got %q, want HTML", payload["parse_mode"])
	}
	if payload["text"] == "" {
		t.Error("text no debe estar vacío")
	}
}

func TestNotifyURLContienePath(t *testing.T) {
	var capturedPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	cfg := telegram.Config{Token: "mi-token-secreto", ChatID: "999"}
	n := telegram.NewForTest(cfg, srv.URL)
	n.Notify(context.Background(), sampleAlert())

	if !strings.Contains(capturedPath, "mi-token-secreto") {
		t.Errorf("path debe contener el token: got %q", capturedPath)
	}
	if !strings.Contains(capturedPath, "sendMessage") {
		t.Errorf("path debe contener sendMessage: got %q", capturedPath)
	}
}

func TestNotifyErrorHTTP500(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	cfg := telegram.Config{Token: "tok", ChatID: "1"}
	n := telegram.NewForTest(cfg, srv.URL)

	err := n.Notify(context.Background(), sampleAlert())
	if err == nil {
		t.Fatal("se esperaba error con HTTP 500")
	}
}

func TestNotifyContextCancelado(t *testing.T) {
	// Servidor que bloquea para que el context se cancele.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancelar inmediatamente

	cfg := telegram.Config{Token: "tok", ChatID: "1"}
	n := telegram.NewForTest(cfg, srv.URL)

	err := n.Notify(ctx, sampleAlert())
	if err == nil {
		t.Fatal("se esperaba error con context cancelado")
	}
}

func TestFormatoContieneIP(t *testing.T) {
	_, _, bodyPtr := okServer(t) // descartamos srv del closure
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*bodyPtr, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	cfg := telegram.Config{Token: "tok", ChatID: "1"}
	n := telegram.NewForTest(cfg, srv.URL)

	alert := sampleAlert()
	alert.IP = "192.168.99.1"
	n.Notify(context.Background(), alert)

	var payload map[string]string
	json.Unmarshal(*bodyPtr, &payload)
	if !strings.Contains(payload["text"], "192.168.99.1") {
		t.Errorf("mensaje debe contener la IP: %s", payload["text"])
	}
}

func TestFormatoSeveridadCritica(t *testing.T) {
	var capturedText string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var payload map[string]string
		json.Unmarshal(body, &payload)
		capturedText = payload["text"]
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	cfg := telegram.Config{Token: "tok", ChatID: "1"}
	n := telegram.NewForTest(cfg, srv.URL)

	alert := sampleAlert()
	alert.Severity = detection.SeveritySuspend
	n.Notify(context.Background(), alert)

	if !strings.Contains(capturedText, "🔴") {
		t.Errorf("alerta crítica debe incluir emoji 🔴: %s", capturedText)
	}
}

func TestFormatoSeveridadAlta(t *testing.T) {
	var capturedText string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var payload map[string]string
		json.Unmarshal(body, &payload)
		capturedText = payload["text"]
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	cfg := telegram.Config{Token: "tok", ChatID: "1"}
	n := telegram.NewForTest(cfg, srv.URL)

	alert := sampleAlert()
	alert.Severity = detection.SeverityRateLimit
	n.Notify(context.Background(), alert)

	if !strings.Contains(capturedText, "🟠") {
		t.Errorf("severidad alta debe incluir emoji 🟠: %s", capturedText)
	}
}

func TestFormatoSinCamposOpcionales(t *testing.T) {
	var capturedText string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var payload map[string]string
		json.Unmarshal(body, &payload)
		capturedText = payload["text"]
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	cfg := telegram.Config{Token: "tok", ChatID: "1"}
	n := telegram.NewForTest(cfg, srv.URL)

	// Alerta mínima: solo módulo y score.
	alert := detection.Alert{
		Module:   "queue_monitor",
		Score:    70,
		Severity: detection.SeverityRateLimit,
		Action:   detection.ActionPurgeQueue,
	}
	if err := n.Notify(context.Background(), alert); err != nil {
		t.Fatalf("Notify: %v", err)
	}
	if capturedText == "" {
		t.Error("se esperaba texto en el mensaje")
	}
}

func TestFormatoContieneTimestamp(t *testing.T) {
	var capturedText string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var payload map[string]string
		json.Unmarshal(body, &payload)
		capturedText = payload["text"]
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	cfg := telegram.Config{Token: "tok", ChatID: "1"}
	n := telegram.NewForTest(cfg, srv.URL)

	alert := sampleAlert() // timestamp: 2024-05-11 10:30:00
	n.Notify(context.Background(), alert)

	if !strings.Contains(capturedText, "2024-05-11") {
		t.Errorf("mensaje debe contener la fecha del timestamp: %s", capturedText)
	}
}
