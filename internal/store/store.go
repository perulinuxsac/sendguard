// Package store implementa la persistencia local del agente usando SQLite embebido
// (modernc.org/sqlite, pure Go, sin CGO). Almacena bans activos y eventos
// pendientes de sincronización con el Controller (StoreAndForward).
//
// Es seguro para uso concurrente: usa SetMaxOpenConns(1) y WAL mode para que
// lectores y escritores no se bloqueen entre sí.
package store

import (
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"

	"github.com/perulinux/sendguard/internal/event"
)

const schema = `
CREATE TABLE IF NOT EXISTS bans (
    ip         TEXT    PRIMARY KEY,
    module     TEXT    NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS pending_events (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    type      TEXT    NOT NULL,
    account   TEXT    NOT NULL DEFAULT '',
    ip        TEXT    NOT NULL DEFAULT '',
    domain    TEXT    NOT NULL DEFAULT '',
    server    TEXT    NOT NULL DEFAULT '',
    country   TEXT    NOT NULL DEFAULT '',
    timestamp INTEGER NOT NULL,
    raw       TEXT    NOT NULL DEFAULT '',
    synced    INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX IF NOT EXISTS idx_pending_events_synced ON pending_events (synced, id);
CREATE INDEX IF NOT EXISTS idx_pending_events_prune  ON pending_events (synced, created_at);
`

// BanRecord describe un ban activo cargado desde la base de datos.
type BanRecord struct {
	IP        string
	Module    string
	ExpiresAt time.Time
}

// PendingEvent envuelve un evento con su ID de base de datos para el StoreAndForward.
type PendingEvent struct {
	ID int64
	event.Event
}

// Store es la capa de persistencia local del agente.
type Store struct {
	db *sql.DB
}

// Open abre (o crea) la base de datos SQLite en path.
// Crea el directorio padre si no existe.
// Activa WAL mode para mejor concurrencia lectura/escritura.
func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("store: crear directorio %s: %w", filepath.Dir(path), err)
	}

	dsn := fmt.Sprintf("file:%s?_journal_mode=WAL&_busy_timeout=5000&_foreign_keys=on", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: abrir %s: %w", path, err)
	}

	// SQLite admite múltiples lectores simultáneos en WAL, pero solo un escritor.
	// Con MaxOpenConns(1) todas las operaciones pasan por una sola conexión y
	// evitamos "database is locked" sin perder rendimiento (el agente no es write-heavy).
	db.SetMaxOpenConns(1)
	db.SetConnMaxLifetime(0)

	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: crear schema: %w", err)
	}

	slog.Info("store: base de datos local abierta", "path", path)
	return &Store{db: db}, nil
}

// Close cierra la conexión a la base de datos.
func (s *Store) Close() error {
	return s.db.Close()
}

// ── Gestión de bans ──────────────────────────────────────────────────────────

// SaveBan persiste un ban activo. Usa INSERT OR REPLACE para actualizar si ya existía.
func (s *Store) SaveBan(ip, module string, expiresAt time.Time) error {
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO bans (ip, module, expires_at, created_at)
		 VALUES (?, ?, ?, unixepoch())`,
		ip, module, expiresAt.Unix(),
	)
	if err != nil {
		return fmt.Errorf("store: SaveBan %s: %w", ip, err)
	}
	return nil
}

// DeleteBan elimina el ban de una IP (llamado desde Unblock).
func (s *Store) DeleteBan(ip string) error {
	_, err := s.db.Exec(`DELETE FROM bans WHERE ip = ?`, ip)
	if err != nil {
		return fmt.Errorf("store: DeleteBan %s: %w", ip, err)
	}
	return nil
}

// LoadActiveBans retorna todos los bans cuya expiración es futura.
// Se llama al arrancar el agente para restaurar el estado en memoria.
func (s *Store) LoadActiveBans() ([]BanRecord, error) {
	rows, err := s.db.Query(
		`SELECT ip, module, expires_at FROM bans WHERE expires_at > unixepoch() ORDER BY created_at`,
	)
	if err != nil {
		return nil, fmt.Errorf("store: LoadActiveBans: %w", err)
	}
	defer rows.Close()

	var bans []BanRecord
	for rows.Next() {
		var b BanRecord
		var expiresUnix int64
		if err := rows.Scan(&b.IP, &b.Module, &expiresUnix); err != nil {
			return nil, fmt.Errorf("store: scan ban: %w", err)
		}
		b.ExpiresAt = time.Unix(expiresUnix, 0)
		bans = append(bans, b)
	}
	return bans, rows.Err()
}

// PruneExpiredBans elimina los bans expirados. Llamar periódicamente para
// evitar que la base de datos crezca indefinidamente.
// Retorna el número de filas eliminadas.
func (s *Store) PruneExpiredBans() (int64, error) {
	res, err := s.db.Exec(`DELETE FROM bans WHERE expires_at <= unixepoch()`)
	if err != nil {
		return 0, fmt.Errorf("store: PruneExpiredBans: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// ── StoreAndForward (preparado para Fase 3 — Controller) ─────────────────────

// SaveEvent persiste un evento para su posterior envío al Controller.
// Los eventos quedan en estado synced=0 hasta que el Controller los confirme.
func (s *Store) SaveEvent(ev event.Event) error {
	_, err := s.db.Exec(
		`INSERT INTO pending_events (type, account, ip, domain, server, country, timestamp, raw)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		string(ev.Type), ev.Account, ev.IP, ev.Domain,
		ev.Server, ev.Country, ev.Timestamp.Unix(), ev.Raw,
	)
	if err != nil {
		return fmt.Errorf("store: SaveEvent: %w", err)
	}
	return nil
}

// LoadUnsynced retorna hasta limit eventos pendientes de sincronización,
// ordenados por ID ascendente para garantizar orden de inserción.
func (s *Store) LoadUnsynced(limit int) ([]PendingEvent, error) {
	rows, err := s.db.Query(
		`SELECT id, type, account, ip, domain, server, country, timestamp, raw
		 FROM pending_events WHERE synced = 0 ORDER BY id LIMIT ?`,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("store: LoadUnsynced: %w", err)
	}
	defer rows.Close()

	var events []PendingEvent
	for rows.Next() {
		var pe PendingEvent
		var ts int64
		var typ string
		if err := rows.Scan(
			&pe.ID, &typ, &pe.Event.Account, &pe.Event.IP, &pe.Event.Domain,
			&pe.Event.Server, &pe.Event.Country, &ts, &pe.Event.Raw,
		); err != nil {
			return nil, fmt.Errorf("store: scan pending event: %w", err)
		}
		pe.Event.Type = event.Type(typ)
		pe.Event.Timestamp = time.Unix(ts, 0)
		events = append(events, pe)
	}
	return events, rows.Err()
}

// MarkSynced marca los eventos con los IDs dados como sincronizados con el Controller.
// Usa una transacción para garantizar atomicidad.
func (s *Store) MarkSynced(ids []int64) error {
	if len(ids) == 0 {
		return nil
	}

	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("store: MarkSynced begin: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`UPDATE pending_events SET synced = 1 WHERE id = ?`)
	if err != nil {
		return fmt.Errorf("store: MarkSynced prepare: %w", err)
	}
	defer stmt.Close()

	for _, id := range ids {
		if _, err := stmt.Exec(id); err != nil {
			return fmt.Errorf("store: MarkSynced id=%d: %w", id, err)
		}
	}
	return tx.Commit()
}

// PruneSyncedEvents elimina eventos ya sincronizados más antiguos que maxAge.
// Evita que la tabla crezca indefinidamente en modo offline.
// maxAge=0 elimina todos los eventos sincronizados sin importar su antigüedad.
func (s *Store) PruneSyncedEvents(maxAge time.Duration) (int64, error) {
	var res sql.Result
	var err error
	if maxAge == 0 {
		res, err = s.db.Exec(`DELETE FROM pending_events WHERE synced = 1`)
	} else {
		cutoff := time.Now().Add(-maxAge).Unix()
		res, err = s.db.Exec(
			`DELETE FROM pending_events WHERE synced = 1 AND created_at <= ?`,
			cutoff,
		)
	}
	if err != nil {
		return 0, fmt.Errorf("store: PruneSyncedEvents: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}
