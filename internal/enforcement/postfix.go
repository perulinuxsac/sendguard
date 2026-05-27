package enforcement

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// accessFileMu serializa lecturas y escrituras concurrentes de sendguard_access
// para evitar que dos expiraciones simultáneas de rate-limit sobreescriban sus cambios mutuamente.
var accessFileMu sync.Mutex

// purgeQueueDomain elimina de la cola diferida de Zimbra todos los mensajes
// cuyo destinatario pertenece al dominio indicado.
//
// postqueue debe ejecutarse como root usando la ruta completa y especificando
// el directorio de config con -c, porque el PATH de root no incluye los
// binarios de Zimbra. postsuper también requiere root.
func purgeQueueDomain(ctx context.Context, domain, sbinDir, confDir string) (int, error) {
	postqueue := filepath.Join(sbinDir, "postqueue")
	out, err := exec.CommandContext(ctx, postqueue, "-c", confDir, "-p").Output()
	if err != nil {
		return 0, fmt.Errorf("postqueue -p: %w", err)
	}

	ids := extractQueueIDs(out, domain)
	if len(ids) == 0 {
		return 0, nil
	}

	postsuper := filepath.Join(sbinDir, "postsuper")
	deleted := 0
	for _, id := range ids {
		if err := exec.CommandContext(ctx, postsuper, "-c", confDir, "-d", id).Run(); err != nil {
			slog.Warn("enforcement: postsuper -d falló", "id", id, "error", err)
			continue
		}
		deleted++
	}
	return deleted, nil
}

// extractQueueIDs parsea la salida de `postqueue -p` y retorna los IDs de los
// mensajes que tienen al menos un destinatario en el dominio dado.
//
// Formato de postqueue -p (cada bloque separado por línea en blanco):
//
//	A8E612F2B1D*    2389 Mon May 11 10:00:00  sender@origen.com
//	                             (error de deferral opcional)
//	                             destinatario@dominio.com
func extractQueueIDs(data []byte, domain string) []string {
	suffix := "@" + strings.ToLower(strings.TrimPrefix(domain, "@"))
	var ids []string
	currentID := ""

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()

		if line == "" {
			currentID = ""
			continue
		}

		// Línea de cabecera de mensaje: empieza por carácter no-espacio y no es '('
		if line[0] != ' ' && line[0] != '\t' && line[0] != '(' {
			fields := strings.Fields(line)
			// Formato: <ID>[*!] <size> <weekday> <month> <day> <time> <sender>
			if len(fields) >= 4 {
				currentID = strings.TrimRight(fields[0], "*!")
			}
			continue
		}

		// Línea de destinatario (empieza por espacio); ignorar líneas de error '(…)'
		// Postfix indenta las líneas de error con espacios antes del '(', por lo que
		// line[0] es espacio — hay que verificar el primer carácter sin espacios.
		if currentID != "" {
			trimmed := strings.TrimSpace(line)
			if trimmed != "" && trimmed[0] != '(' && strings.Contains(strings.ToLower(trimmed), suffix) {
				ids = append(ids, currentID)
				// Resetear para no agregar el mismo ID por múltiples rcpt del mismo dominio.
				currentID = ""
			}
		}
	}
	return ids
}

// rateLimit agrega una cuenta a la tabla de acceso de Zimbra/Postfix y
// reconstruye el mapa con postmap (como root) para que el rechazo sea inmediato.
// Si banSeconds > 0, programa la eliminación automática de la entrada.
//
// El access file se crea en confDir/sendguard_access.
// Requiere que el administrador haya configurado una vez:
//
//	zmprov mcf zimbraMtaSmtpdSenderRestrictions \
//	    "check_sender_access lmdb:<confDir>/sendguard_access" \
//	    "permit_sasl_authenticated" \
//	    "reject_unauthenticated_sender_login_mismatch"
func rateLimit(ctx context.Context, account string, banSeconds int, sbinDir, confDir string) error {
	accessFile := filepath.Join(confDir, "sendguard_access")
	entry := account + " REJECT SendGuard: limite de envio excedido\n"

	// Serializar contra removeRateLimit para evitar que una expiración concurrente
	// lea el archivo antes de que este append y la regeneración del mapa queden fijos.
	accessFileMu.Lock()
	f, err := os.OpenFile(accessFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		accessFileMu.Unlock()
		return fmt.Errorf("abrir access file %s: %w", accessFile, err)
	}
	if _, err := f.WriteString(entry); err != nil {
		f.Close()
		accessFileMu.Unlock()
		return fmt.Errorf("escribir en access file: %w", err)
	}
	f.Close()

	postmap := filepath.Join(sbinDir, "postmap")
	out, err := exec.CommandContext(ctx, postmap, "lmdb:"+accessFile).CombinedOutput()
	accessFileMu.Unlock()
	if err != nil {
		return fmt.Errorf("postmap lmdb:%s: %w (output: %s)", accessFile, err, string(out))
	}

	if banSeconds > 0 {
		time.AfterFunc(time.Duration(banSeconds)*time.Second, func() {
			removeRateLimit(account, sbinDir, confDir)
		})
	}
	return nil
}

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
	out, err := exec.CommandContext(ctx, postqueue, "-c", confDir, "-p").Output()
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

// removeRateLimit elimina la línea del account del access file y regenera el mapa.
// Se llama desde un time.AfterFunc cuando expira el ban.
func removeRateLimit(account, sbinDir, confDir string) {
	accessFile := filepath.Join(confDir, "sendguard_access")
	prefix := account + " "

	accessFileMu.Lock()
	defer accessFileMu.Unlock()

	data, err := os.ReadFile(accessFile)
	if err != nil {
		slog.Warn("enforcement: no se pudo leer access file para limpiar rate-limit",
			"account", account, "error", err)
		return
	}

	var filtered []byte
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, prefix) {
			filtered = append(filtered, []byte(line+"\n")...)
		}
	}
	if err := scanner.Err(); err != nil {
		slog.Warn("enforcement: error leyendo access file, se cancela la limpieza de rate-limit",
			"account", account, "error", err)
		return
	}

	if err := os.WriteFile(accessFile, filtered, 0644); err != nil {
		slog.Warn("enforcement: no se pudo actualizar access file", "account", account, "error", err)
		return
	}

	postmap := filepath.Join(sbinDir, "postmap")
	if err := exec.Command(postmap, "lmdb:"+accessFile).Run(); err != nil {
		slog.Warn("enforcement: postmap falló al limpiar rate-limit", "account", account, "error", err)
		return
	}
	slog.Info("enforcement: rate-limit eliminado", "account", account)
}
