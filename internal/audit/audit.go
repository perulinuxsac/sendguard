// Package audit escribe un registro estructurado de cada acción de contención
// ejecutada por el Enforcer. Cada línea es un JSON válido (NDJSON) para facilitar
// el procesamiento con herramientas como jq, Loki, o Elasticsearch.
//
// El archivo se abre en modo append y se crea si no existe.
// Es seguro para escrituras concurrentes (usa sync.Mutex).
package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/perulinux/sendguard/internal/detection"
)

// Entry representa una acción de contención registrada.
type Entry struct {
	Timestamp time.Time `json:"timestamp"`
	Action    string    `json:"action"`
	Module    string    `json:"module"`
	Score     int       `json:"score"`
	Severity  int       `json:"severity"`
	IP        string    `json:"ip,omitempty"`
	Account   string    `json:"account,omitempty"`
	Domain    string    `json:"domain,omitempty"`
	Server    string    `json:"server,omitempty"`
	Reasons   []string  `json:"reasons,omitempty"`
}

// Logger escribe entradas de auditoría en un archivo NDJSON.
type Logger struct {
	mu  sync.Mutex
	out io.Writer
}

// New abre (o crea) el archivo en path y retorna un Logger listo para usar.
// Retorna error si no se puede abrir el archivo.
func New(path string) (*Logger, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, fmt.Errorf("audit: abrir %s: %w", path, err)
	}
	return &Logger{out: f}, nil
}

// NewWithWriter crea un Logger que escribe en w. Útil para tests.
func NewWithWriter(w io.Writer) *Logger {
	return &Logger{out: w}
}

// Log registra la acción de contención descrita por la alerta.
// Si la serialización JSON falla se loguea el error pero nunca se bloquea.
func (l *Logger) Log(_ context.Context, alert detection.Alert) {
	entry := Entry{
		Timestamp: alert.Timestamp,
		Action:    string(alert.Action),
		Module:    alert.Module,
		Score:     alert.Score,
		Severity:  int(alert.Severity),
		IP:        alert.IP,
		Account:   alert.Account,
		Domain:    alert.Domain,
		Server:    alert.Server,
		Reasons:   alert.Reasons,
	}

	data, err := json.Marshal(entry)
	if err != nil {
		slog.Error("audit: no se pudo serializar entrada", "error", err)
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.out, "%s\n", data)
}
