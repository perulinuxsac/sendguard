package webhook

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
)

func makeAlert(opts ...func(*detection.Alert)) detection.Alert {
	a := detection.Alert{
		Module:    "auth_failed",
		Action:    detection.ActionBlockIP,
		Severity:  detection.SeveritySuspend,
		Score:     95,
		IP:        "1.2.3.4",
		Timestamp: time.Now(),
		Reasons:   []string{"5 fallos en 60s"},
	}
	for _, o := range opts {
		o(&a)
	}
	return a
}

func TestNotifyEnviaPost(t *testing.T) {
	var got *http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := NewForTest(Config{}, srv.URL)
	if err := n.Notify(context.Background(), makeAlert()); err != nil {
		t.Fatalf("Notify: %v", err)
	}
	if got == nil {
		t.Fatal("el servidor no recibió ninguna petición")
	}
	if got.Method != http.MethodPost {
		t.Errorf("método: got %q, want POST", got.Method)
	}
}

func TestNotifyContentTypeJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ct := r.Header.Get("Content-Type")
		if ct != "application/json" {
			t.Errorf("Content-Type: got %q, want application/json", ct)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := NewForTest(Config{}, srv.URL)
	n.Notify(context.Background(), makeAlert())
}

func TestNotifyPayloadCampos(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		json.Unmarshal(data, &body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := NewForTest(Config{}, srv.URL)
	n.Notify(context.Background(), makeAlert())

	if body["source"] != "sendguard" {
		t.Errorf("source: got %v, want sendguard", body["source"])
	}
	if body["module"] != "auth_failed" {
		t.Errorf("module: got %v, want auth_failed", body["module"])
	}
	if body["ip"] != "1.2.3.4" {
		t.Errorf("ip: got %v, want 1.2.3.4", body["ip"])
	}
	if body["action"] != "block_ip" {
		t.Errorf("action: got %v, want block_ip", body["action"])
	}
	if body["text"] == "" {
		t.Error("text no debe ser vacío")
	}
}

func TestNotifyError4xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	n := NewForTest(Config{}, srv.URL)
	if err := n.Notify(context.Background(), makeAlert()); err == nil {
		t.Error("debe retornar error cuando el servidor responde 5xx")
	}
}

func TestNotifyContextCancelado(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	n := NewForTest(Config{}, srv.URL)
	if err := n.Notify(ctx, makeAlert()); err == nil {
		t.Error("contexto cancelado debe retornar error")
	}
}

func TestNotifyURLInvalida(t *testing.T) {
	n := NewForTest(Config{}, "http://127.0.0.1:1") // puerto cerrado
	err := n.Notify(context.Background(), makeAlert())
	if err == nil {
		t.Error("URL inalcanzable debe retornar error")
	}
}

// --- formatText ---

func TestFormatTextConIPYCuenta(t *testing.T) {
	a := makeAlert(func(a *detection.Alert) {
		a.Account = "user@example.com"
	})
	text := formatText(a)
	if text == "" {
		t.Error("formatText no debe retornar cadena vacía")
	}
	// Debe contener tanto la IP como la cuenta.
	for _, want := range []string{"1.2.3.4", "user@example.com"} {
		if !strings.Contains(text, want) {
			t.Errorf("formatText no contiene %q: %q", want, text)
		}
	}
}

func TestFormatTextSoloCuenta(t *testing.T) {
	a := makeAlert(func(a *detection.Alert) {
		a.IP = ""
		a.Account = "user@example.com"
	})
	text := formatText(a)
	if !strings.Contains(text, "user@example.com") {
		t.Errorf("formatText no contiene cuenta: %q", text)
	}
}

func TestFormatTextSinContexto(t *testing.T) {
	a := makeAlert(func(a *detection.Alert) {
		a.IP = ""
		a.Account = ""
	})
	text := formatText(a)
	if text == "" {
		t.Error("formatText no debe retornar cadena vacía sin IP ni cuenta")
	}
}

func TestFormatTextSeverityLabels(t *testing.T) {
	casos := []struct {
		severity detection.Severity
		label    string
	}{
		{detection.SeverityLog, "INFO"},
		{detection.SeverityWarn, "WARN"},
		{detection.SeverityRateLimit, "RATE-LIMIT"},
		{detection.SeveritySuspend, "CRÍTICO"},
	}
	for _, c := range casos {
		a := makeAlert(func(a *detection.Alert) { a.Severity = c.severity })
		text := formatText(a)
		if !strings.Contains(text, c.label) {
			t.Errorf("severity %d: texto no contiene %q: %q", c.severity, c.label, text)
		}
	}
}
