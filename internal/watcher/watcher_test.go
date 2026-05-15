package watcher

import (
	"os"
	"testing"
	"time"

	"github.com/perulinux/sendguard/internal/event"
)

// parseFn simple: acepta cualquier línea no vacía como AuthFailed con IP "1.2.3.4".
func stubParse(line string) (event.Event, bool) {
	if line == "" {
		return event.Event{}, false
	}
	return event.Event{
		Type:      event.AuthFailed,
		IP:        "1.2.3.4",
		Timestamp: time.Now(),
		Raw:       line,
	}, true
}

// parseFnConServer: simula parser que no rellena Server (como mailbox.log).
func stubParseNoServer(line string) (event.Event, bool) {
	if line == "" {
		return event.Event{}, false
	}
	return event.Event{
		Type:      event.AuthFailed,
		Timestamp: time.Now(),
		Raw:       line,
	}, true
}

// newTempFile crea un archivo temporal y retorna el *os.File ya abierto para lectura.
func newTempFile(t *testing.T, content string) *os.File {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "watcher_test_*.log")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	if content != "" {
		if _, err := f.WriteString(content); err != nil {
			t.Fatalf("WriteString: %v", err)
		}
	}
	// Reposicionar al inicio para que drainLines pueda leer.
	if _, err := f.Seek(0, 0); err != nil {
		t.Fatalf("Seek: %v", err)
	}
	return f
}

// --- drainLines ---

func TestDrainLinesLineaCompleta(t *testing.T) {
	f := newTempFile(t, "line one\nline two\n")
	defer f.Close()

	ch := make(chan event.Event, 10)
	w := New(f.Name(), stubParse, "", ch)
	w.drainLines(f)

	if len(ch) != 2 {
		t.Fatalf("got %d eventos, want 2", len(ch))
	}
}

func TestDrainLinesLineaParcialIgnorada(t *testing.T) {
	// "partial" no termina en '\n' — no debe emitirse como evento.
	f := newTempFile(t, "complete line\npartial")
	defer f.Close()

	ch := make(chan event.Event, 10)
	w := New(f.Name(), stubParse, "", ch)
	w.drainLines(f)

	if len(ch) != 1 {
		t.Fatalf("got %d eventos, want 1 (línea parcial ignorada)", len(ch))
	}
	ev := <-ch
	if ev.Raw != "complete line" {
		t.Errorf("Raw: got %q, want \"complete line\"", ev.Raw)
	}
}

func TestDrainLinesSeekDeVueltaALineaParcial(t *testing.T) {
	// Verificar que después de drainLines el cursor queda justo después de la
	// última '\n', para que la siguiente llamada retome la línea parcial.
	f := newTempFile(t, "first\nsecond\nincomplete")
	defer f.Close()

	ch := make(chan event.Event, 10)
	w := New(f.Name(), stubParse, "", ch)
	w.drainLines(f)

	// El cursor debe estar en la posición después de "second\n" (= 13 bytes).
	pos, err := f.Seek(0, 1) // SeekCurrent
	if err != nil {
		t.Fatalf("Seek: %v", err)
	}
	expected := int64(len("first\nsecond\n"))
	if pos != expected {
		t.Errorf("posición después de drainLines: got %d, want %d", pos, expected)
	}
}

func TestDrainLinesArchivoVacio(t *testing.T) {
	f := newTempFile(t, "")
	defer f.Close()

	ch := make(chan event.Event, 10)
	w := New(f.Name(), stubParse, "", ch)
	w.drainLines(f) // no debe panic ni bloquear

	if len(ch) != 0 {
		t.Errorf("archivo vacío: got %d eventos, want 0", len(ch))
	}
}

func TestDrainLinesSoloLineaVacia(t *testing.T) {
	f := newTempFile(t, "\n\n")
	defer f.Close()

	ch := make(chan event.Event, 10)
	w := New(f.Name(), stubParse, "", ch)
	w.drainLines(f)

	// stubParse rechaza líneas vacías → 0 eventos.
	if len(ch) != 0 {
		t.Errorf("solo newlines: got %d eventos, want 0", len(ch))
	}
}

func TestDrainLinesLlamadasConsecutivas(t *testing.T) {
	// Simula que llegan líneas en dos ráfagas (como en producción con Write events).
	f := newTempFile(t, "batch one\n")
	defer f.Close()

	ch := make(chan event.Event, 10)
	w := New(f.Name(), stubParse, "", ch)
	w.drainLines(f)

	if len(ch) != 1 {
		t.Fatalf("primera ráfaga: got %d eventos, want 1", len(ch))
	}

	// Abrir un fd independiente para escribir — simula el demonio de log que
	// escribe por su propio descriptor sin afectar el cursor del lector.
	wf, err := os.OpenFile(f.Name(), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("OpenFile para escritura: %v", err)
	}
	defer wf.Close()
	if _, err := wf.WriteString("batch two\nbatch three\n"); err != nil {
		t.Fatalf("WriteString: %v", err)
	}
	w.drainLines(f)

	if len(ch) != 3 {
		t.Fatalf("segunda ráfaga: got %d eventos acumulados, want 3", len(ch))
	}
}

func TestDrainLinesCanalLlenoDescarta(t *testing.T) {
	// Canal con capacidad 0 — drainLines no debe bloquearse.
	f := newTempFile(t, "line one\nline two\n")
	defer f.Close()

	ch := make(chan event.Event, 0)
	w := New(f.Name(), stubParse, "", ch)

	done := make(chan struct{})
	go func() {
		w.drainLines(f)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("drainLines bloqueó con canal lleno")
	}
}

func TestDrainLinesParseFnRechaza(t *testing.T) {
	// parseFn que rechaza todas las líneas.
	rejectAll := func(line string) (event.Event, bool) { return event.Event{}, false }

	f := newTempFile(t, "ignored line\nanother ignored\n")
	defer f.Close()

	ch := make(chan event.Event, 10)
	w := New(f.Name(), rejectAll, "", ch)
	w.drainLines(f)

	if len(ch) != 0 {
		t.Errorf("parseFn que rechaza: got %d eventos, want 0", len(ch))
	}
}

// --- server override ---

func TestDrainLinesServerRellena(t *testing.T) {
	// Cuando parseFn no rellena Server, el watcher debe hacerlo.
	f := newTempFile(t, "some log line\n")
	defer f.Close()

	ch := make(chan event.Event, 10)
	w := New(f.Name(), stubParseNoServer, "mail.example.com", ch)
	w.drainLines(f)

	if len(ch) != 1 {
		t.Fatalf("got %d eventos, want 1", len(ch))
	}
	ev := <-ch
	if ev.Server != "mail.example.com" {
		t.Errorf("Server: got %q, want \"mail.example.com\"", ev.Server)
	}
}

func TestDrainLinesServerSobreescribe(t *testing.T) {
	// El server ID configurado en el watcher siempre sobreescribe el que
	// parseFn extrae del hostname del log. Esto garantiza que el server_id
	// del agent.yaml (FQDN) se use en todos los eventos, no el hostname corto.
	parseConServer := func(line string) (event.Event, bool) {
		return event.Event{
			Type:      event.AuthFailed,
			Server:    "short-hostname",
			Timestamp: time.Now(),
			Raw:       line,
		}, true
	}

	f := newTempFile(t, "some line\n")
	defer f.Close()

	ch := make(chan event.Event, 10)
	w := New(f.Name(), parseConServer, "mail.perulinux.pe", ch)
	w.drainLines(f)

	if len(ch) != 1 {
		t.Fatalf("got %d eventos, want 1", len(ch))
	}
	ev := <-ch
	if ev.Server != "mail.perulinux.pe" {
		t.Errorf("Server: got %q, want \"mail.perulinux.pe\" (watcher debe sobreescribir con FQDN)", ev.Server)
	}
}
