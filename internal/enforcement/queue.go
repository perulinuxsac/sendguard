package enforcement

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"strings"
)

// Lectura de la cola de Postfix, solo para observabilidad (GET /queue y
// `sendguard-ctl queue`). SendGuard no modifica la cola ni la configuración
// SMTP: la contención es únicamente por firewall (ipset/ufw) y suspensión de
// cuenta (zmprov).

// QueueEntry representa un mensaje en la cola diferida de Postfix.
type QueueEntry struct {
	ID         string   `json:"id"`
	Size       int      `json:"size"`
	Sender     string   `json:"sender"`
	Recipients []string `json:"recipients"`
}

// ListQueue retorna todos los mensajes actualmente en la cola de Postfix.
// Retorna slice vacío (no error) si la cola está vacía.
func ListQueue(ctx context.Context, sbinDir, confDir string) ([]QueueEntry, error) {
	postqueue := filepath.Join(sbinDir, "postqueue")
	out, err := newCmd(ctx, postqueue, "-c", confDir, "-p").Output()
	if err != nil {
		return nil, fmt.Errorf("postqueue -p: %w", err)
	}
	return parseQueueFull(out), nil
}

// parseQueueFull parsea la salida completa de `postqueue -p` en structs QueueEntry.
func parseQueueFull(data []byte) []QueueEntry {
	var entries []QueueEntry
	var current *QueueEntry

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			if current != nil {
				entries = append(entries, *current)
				current = nil
			}
			continue
		}
		// Línea de cabecera: no empieza con espacio ni con '('
		if line[0] != ' ' && line[0] != '\t' && line[0] != '(' {
			fields := strings.Fields(line)
			if len(fields) >= 4 {
				var size int
				// Verificar que el segundo campo es un número (filtra "Mail queue is empty" y la cabecera)
				if n, _ := fmt.Sscanf(fields[1], "%d", &size); n == 1 {
					current = &QueueEntry{
						ID:     strings.TrimRight(fields[0], "*!"),
						Size:   size,
						Sender: fields[len(fields)-1],
					}
				}
			}
			continue
		}
		// Línea de destinatario (empieza por espacio); ignorar líneas de error '(…)'
		// Postfix indenta los mensajes de error con espacios antes del '(', por lo que
		// hay que verificar el primer carácter tras el trim, no line[0].
		if current != nil {
			trimmed := strings.TrimSpace(line)
			if trimmed != "" && trimmed[0] != '(' {
				current.Recipients = append(current.Recipients, trimmed)
			}
		}
	}
	// Volcar última entrada si no hay línea en blanco al final
	if current != nil {
		entries = append(entries, *current)
	}
	return entries
}
