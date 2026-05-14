// Package watcher implementa un lector de logs en tiempo real con soporte
// para rotación de archivos (logrotate). Usa inotify en Linux vía fsnotify.
//
// Un mismo Watcher puede servir tanto /var/log/mail.log como
// /opt/zimbra/log/mailbox.log: la lógica de parseo se inyecta como función.
package watcher

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/perulinux/sendguard/internal/event"
)

const (
	retryDelay   = 5 * time.Second // espera antes de reintentar al fallar apertura
	rotationWait = 2 * time.Second // espera máxima a que el nuevo archivo aparezca tras rotación
)

// Watcher lee un archivo de log en tiempo real y envía eventos parseados al canal.
type Watcher struct {
	path    string
	parseFn func(string) (event.Event, bool) // función de parseo inyectada
	server  string                           // si no vacío, rellena ev.Server cuando el parser no lo hace
	eventCh chan<- event.Event
}

// New crea un Watcher para el archivo en path.
//
// parseFn es la función que convierte cada línea en un evento; se puede pasar
// p.ParseLine (para mail.log) o p.ParseMailboxLine (para mailbox.log).
//
// server se usa para rellenar ev.Server en logs que no incluyen el hostname
// en cada línea (como mailbox.log). Pasar "" para mail.log, donde el hostname
// ya viene en la cabecera syslog y el parser lo extrae.
//
// eventCh recibe los eventos reconocidos; el llamante es responsable de consumirlo.
func New(path string, parseFn func(string) (event.Event, bool), server string, eventCh chan<- event.Event) *Watcher {
	return &Watcher{
		path:    path,
		parseFn: parseFn,
		server:  server,
		eventCh: eventCh,
	}
}

// Run arranca el watcher y bloquea hasta que ctx sea cancelado.
// Si ocurre un error (ej. archivo no encontrado), reintenta cada retryDelay.
func (w *Watcher) Run(ctx context.Context) {
	for {
		err := w.tail(ctx)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			slog.Error("watcher: error, reintentando", "path", w.path, "error", err, "delay", retryDelay)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(retryDelay):
		}
	}
}

// tail abre el archivo, se posiciona al final y lee nuevas líneas hasta que:
//   - ctx es cancelado (retorna nil)
//   - el archivo es rotado (retorna nil para que Run reabra desde el inicio)
//   - ocurre un error irrecuperable (retorna el error)
func (w *Watcher) tail(ctx context.Context) error {
	f, err := os.Open(w.path)
	if err != nil {
		return fmt.Errorf("abrir %s: %w", w.path, err)
	}
	defer f.Close()

	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		return fmt.Errorf("seek %s: %w", w.path, err)
	}

	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("fsnotify.NewWatcher: %w", err)
	}
	defer fsw.Close()

	dir := filepath.Dir(w.path)
	for _, target := range []string{w.path, dir} {
		if err := fsw.Add(target); err != nil {
			return fmt.Errorf("fsnotify.Add(%s): %w", target, err)
		}
	}

	slog.Info("watcher: siguiendo archivo", "path", w.path)

	for {
		w.drainLines(f)

		select {
		case <-ctx.Done():
			return nil

		case fsEv, ok := <-fsw.Events:
			if !ok {
				return fmt.Errorf("canal fsnotify cerrado inesperadamente")
			}

			switch {
			case fsEv.Has(fsnotify.Write):
				// Nueva data: el próximo ciclo drainLines la leerá.

			case fsEv.Has(fsnotify.Remove) || fsEv.Has(fsnotify.Rename):
				if filepath.Clean(fsEv.Name) == filepath.Clean(w.path) {
					slog.Info("watcher: archivo rotado, esperando nuevo archivo", "path", w.path)
					w.drainLines(f)
					w.waitForNewFile(ctx, w.path)
					return nil
				}

			case fsEv.Has(fsnotify.Create):
				if filepath.Clean(fsEv.Name) == filepath.Clean(w.path) {
					slog.Info("watcher: nuevo archivo detectado", "path", w.path)
					return nil
				}
			}

		case err := <-fsw.Errors:
			slog.Warn("watcher: error fsnotify", "path", w.path, "error", err)
		}
	}
}

// drainLines lee todas las líneas completas desde la posición actual de f.
// Usa bufio.Reader en lugar de bufio.Scanner para evitar la pérdida de líneas
// parciales: Scanner avanza el file offset incluso cuando la línea no termina
// en '\n', y los bytes parciales quedan atrapados en su buffer interno.
// Aquí llevamos un cursor explícito y hacemos Seek de vuelta al final de la
// última línea completa antes de salir.
func (w *Watcher) drainLines(f *os.File) {
	startPos, err := f.Seek(0, io.SeekCurrent)
	if err != nil {
		slog.Warn("watcher: seek actual fallido", "path", w.path, "error", err)
		return
	}

	reader := bufio.NewReader(f)
	lastLineEndPos := startPos

	for {
		line, err := reader.ReadString('\n')
		if err == io.EOF {
			// Devolver el cursor al final de la última línea completa leída.
			if _, seekErr := f.Seek(lastLineEndPos, io.SeekStart); seekErr != nil {
				slog.Warn("watcher: seek de restauración fallido", "path", w.path, "error", seekErr)
			}
			return
		}
		if err != nil {
			slog.Warn("watcher: error leyendo log", "path", w.path, "error", err)
			return
		}

		lastLineEndPos += int64(len(line))
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			continue
		}

		ev, ok := w.parseFn(line)
		if !ok {
			continue
		}
		if w.server != "" && ev.Server == "" {
			ev.Server = w.server
		}
		select {
		case w.eventCh <- ev:
		default:
			slog.Warn("watcher: canal lleno, descartando evento", "path", w.path, "line", line)
		}
	}
}

// waitForNewFile espera hasta rotationWait a que el archivo reaparezca en disco.
func (w *Watcher) waitForNewFile(ctx context.Context, path string) {
	deadline := time.After(rotationWait)
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-deadline:
			return
		case <-tick.C:
			if _, err := os.Stat(path); err == nil {
				return
			}
		}
	}
}
