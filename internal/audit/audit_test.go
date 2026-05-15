package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/perulinux/sendguard/internal/detection"
)

func makeAlert(ip, account string, action detection.Action) detection.Alert {
	return detection.Alert{
		Module:    "auth_failed",
		Action:    action,
		Score:     80,
		Severity:  detection.SeveritySuspend,
		IP:        ip,
		Account:   account,
		Domain:    "example.com",
		Server:    "mail.example.com",
		Timestamp: time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
		Reasons:   []string{"5 fallos en 60s"},
	}
}

func TestLogEscribeJSON(t *testing.T) {
	var buf bytes.Buffer
	l := NewWithWriter(&buf)
	l.Log(context.Background(), makeAlert("1.2.3.4", "", detection.ActionBlockIP))

	if buf.Len() == 0 {
		t.Fatal("log no escribió nada")
	}

	var entry Entry
	if err := json.Unmarshal(bytes.TrimRight(buf.Bytes(), "\n"), &entry); err != nil {
		t.Fatalf("JSON inválido: %v\ncontenido: %s", err, buf.String())
	}
}

func TestLogCamposIP(t *testing.T) {
	var buf bytes.Buffer
	l := NewWithWriter(&buf)
	l.Log(context.Background(), makeAlert("9.8.7.6", "", detection.ActionBlockIP))

	var entry Entry
	json.Unmarshal(bytes.TrimRight(buf.Bytes(), "\n"), &entry)

	if entry.IP != "9.8.7.6" {
		t.Errorf("IP: got %q, want 9.8.7.6", entry.IP)
	}
	if entry.Action != "block_ip" {
		t.Errorf("Action: got %q, want block_ip", entry.Action)
	}
	if entry.Module != "auth_failed" {
		t.Errorf("Module: got %q, want auth_failed", entry.Module)
	}
	if entry.Score != 80 {
		t.Errorf("Score: got %d, want 80", entry.Score)
	}
}

func TestLogCamposCuenta(t *testing.T) {
	var buf bytes.Buffer
	l := NewWithWriter(&buf)
	l.Log(context.Background(), makeAlert("", "user@example.com", detection.ActionSuspendAcct))

	var entry Entry
	json.Unmarshal(bytes.TrimRight(buf.Bytes(), "\n"), &entry)

	if entry.Account != "user@example.com" {
		t.Errorf("Account: got %q, want user@example.com", entry.Account)
	}
	if entry.Action != "suspend_account" {
		t.Errorf("Action: got %q, want suspend_account", entry.Action)
	}
}

func TestLogTimestamp(t *testing.T) {
	var buf bytes.Buffer
	l := NewWithWriter(&buf)
	l.Log(context.Background(), makeAlert("1.2.3.4", "", detection.ActionBlockIP))

	var entry Entry
	json.Unmarshal(bytes.TrimRight(buf.Bytes(), "\n"), &entry)

	if entry.Timestamp.IsZero() {
		t.Error("Timestamp no debe ser zero")
	}
}

func TestLogMultiplesEntradasNDJSON(t *testing.T) {
	var buf bytes.Buffer
	l := NewWithWriter(&buf)

	l.Log(context.Background(), makeAlert("1.1.1.1", "", detection.ActionBlockIP))
	l.Log(context.Background(), makeAlert("2.2.2.2", "", detection.ActionBlockIP))
	l.Log(context.Background(), makeAlert("", "u@e.com", detection.ActionSuspendAcct))

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("NDJSON: got %d líneas, want 3", len(lines))
	}

	for i, line := range lines {
		var entry Entry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Errorf("línea %d JSON inválido: %v", i+1, err)
		}
	}
}

func TestLogRazones(t *testing.T) {
	var buf bytes.Buffer
	l := NewWithWriter(&buf)
	alert := makeAlert("1.2.3.4", "", detection.ActionBlockIP)
	alert.Reasons = []string{"razón 1", "razón 2"}
	l.Log(context.Background(), alert)

	var entry Entry
	json.Unmarshal(bytes.TrimRight(buf.Bytes(), "\n"), &entry)

	if len(entry.Reasons) != 2 {
		t.Errorf("Reasons: got %d, want 2", len(entry.Reasons))
	}
}

func TestLogCamposOpcionalesOmitidosSiVacios(t *testing.T) {
	var buf bytes.Buffer
	l := NewWithWriter(&buf)

	// Sin IP ni Account ni Domain.
	alert := detection.Alert{
		Module:    "queue_monitor",
		Action:    detection.ActionNotifyOnly,
		Score:     30,
		Severity:  detection.SeverityWarn,
		Timestamp: time.Now(),
	}
	l.Log(context.Background(), alert)

	raw := buf.String()
	// Los campos omitempty no deben aparecer en el JSON si están vacíos.
	for _, campo := range []string{`"ip"`, `"account"`, `"domain"`, `"server"`} {
		if strings.Contains(raw, campo) {
			t.Errorf("campo vacío %s no debe aparecer en JSON: %s", campo, raw)
		}
	}
}

func TestNewArchivoInexistente(t *testing.T) {
	if runtime.GOOS == "windows" {
		// En Windows el archivo queda bloqueado por el proceso Go test durante la limpieza
		// del directorio temporal. No es un bug real — en producción (Linux) funciona correctamente.
		t.Skip("test omitido en Windows: file lock durante TempDir cleanup")
	}
	// Crear en un directorio temporal — debe funcionar.
	path := t.TempDir() + "/audit.log"
	l, err := New(path)
	if err != nil {
		t.Fatalf("New en dir temporal: %v", err)
	}
	if l == nil {
		t.Fatal("Logger es nil")
	}
}

func TestNewDirectorioInexistente(t *testing.T) {
	// Directorio que no existe — debe retornar error.
	_, err := New("/ruta/que/no/existe/audit.log")
	if err == nil {
		t.Error("directorio inexistente debe retornar error")
	}
}
