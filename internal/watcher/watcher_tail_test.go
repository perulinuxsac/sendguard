package watcher

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/perulinux/sendguard/internal/event"
)

// ── waitForNewFile ────────────────────────────────────────────────────────────

func TestWaitForNewFile_FileYaExiste(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "*.log")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	ch := make(chan event.Event, 10)
	w := New(f.Name(), stubParse, "", ch)

	start := time.Now()
	w.waitForNewFile(context.Background(), f.Name())

	if time.Since(start) > 500*time.Millisecond {
		t.Error("waitForNewFile tardó demasiado con archivo ya existente")
	}
}

func TestWaitForNewFile_CtxCancelado(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/inexistente.log"

	ch := make(chan event.Event, 10)
	w := New(path, stubParse, "", ch)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancelado

	start := time.Now()
	w.waitForNewFile(ctx, path)

	if time.Since(start) > 500*time.Millisecond {
		t.Error("waitForNewFile no respetó ctx cancelado")
	}
}

func TestWaitForNewFile_FileAparece(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/nuevo.log"

	ch := make(chan event.Event, 10)
	w := New(path, stubParse, "", ch)

	go func() {
		time.Sleep(100 * time.Millisecond)
		os.WriteFile(path, []byte{}, 0644)
	}()

	start := time.Now()
	w.waitForNewFile(context.Background(), path)

	// Debe detectar el archivo antes de rotationWait (2s)
	if time.Since(start) > 1500*time.Millisecond {
		t.Error("waitForNewFile no detectó el archivo nuevo a tiempo")
	}
}

// ── tail ─────────────────────────────────────────────────────────────────────

func TestTail_CtxCancelado(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "*.log")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	ch := make(chan event.Event, 10)
	w := New(f.Name(), stubParse, "", ch)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err = w.tail(ctx)
	if err != nil {
		t.Errorf("tail con ctx cancelado debe retornar nil, got: %v", err)
	}
}

func TestTail_ArchivoNoExiste(t *testing.T) {
	ch := make(chan event.Event, 10)
	w := New("/no/existe/archivo.log", stubParse, "", ch)

	err := w.tail(context.Background())
	if err == nil {
		t.Error("tail con archivo inexistente debe retornar error")
	}
}

func TestTail_LeeLineasNuevas(t *testing.T) {
	// Test de integración: tail recibe líneas via inotify Write event.
	f, err := os.CreateTemp(t.TempDir(), "*.log")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	ch := make(chan event.Event, 10)
	w := New(f.Name(), stubParse, "", ch)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- w.tail(ctx)
	}()

	// Esperar a que tail abra el archivo y se posicione al final
	time.Sleep(50 * time.Millisecond)

	// Escribir desde un fd independiente (simula el demonio de log)
	wf, err := os.OpenFile(f.Name(), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	defer wf.Close()
	wf.WriteString("nueva linea\n")

	// Esperar el evento
	select {
	case ev := <-ch:
		if ev.Raw != "nueva linea" {
			t.Errorf("Raw: got %q, want \"nueva linea\"", ev.Raw)
		}
	case <-time.After(3 * time.Second):
		t.Error("timeout esperando evento de escritura via inotify")
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("tail: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("tail no terminó tras cancelar ctx")
	}
}

func TestTail_Rotacion(t *testing.T) {
	// Simula logrotate: rename del archivo activo + creación de uno nuevo.
	// tail debe detectar el Rename/Remove, llamar a waitForNewFile y retornar nil.
	dir := t.TempDir()
	path := dir + "/rotate.log"
	if err := os.WriteFile(path, []byte{}, 0644); err != nil {
		t.Fatal(err)
	}

	ch := make(chan event.Event, 10)
	w := New(path, stubParse, "", ch)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- w.tail(ctx)
	}()

	time.Sleep(50 * time.Millisecond)

	// Rotación: renombrar archivo viejo y crear uno nuevo (como logrotate).
	os.Rename(path, path+".1")
	os.WriteFile(path, []byte{}, 0644)

	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("tail tras rotación debe retornar nil, got: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("tail no detectó la rotación del archivo")
	}
}

// ── Run ──────────────────────────────────────────────────────────────────────

func TestRun_CtxCancelado(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "*.log")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	ch := make(chan event.Event, 10)
	w := New(f.Name(), stubParse, "", ch)

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		w.Run(ctx)
		close(done)
	}()

	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run no terminó tras cancelar ctx")
	}
}

func TestRun_ArchivoInexistenteSaleConTimeout(t *testing.T) {
	// Con archivo inexistente, tail retorna error y Run reintenta.
	// El ctx expira (100ms) y Run debe salir durante el select de retryDelay.
	ch := make(chan event.Event, 10)
	w := New("/no/existe/archivo.log", stubParse, "", ch)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() {
		w.Run(ctx)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run no terminó cuando ctx expiró con archivo inexistente")
	}
}
