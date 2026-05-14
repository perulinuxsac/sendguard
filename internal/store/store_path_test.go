package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/perulinux/sendguard/internal/event"
)

func TestOpenCreaDirectorioAnidado(t *testing.T) {
	// Open debe crear el directorio padre automáticamente.
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "dir", "sendguard.db")

	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open con ruta anidada: %v", err)
	}
	defer s.Close()

	// Verificar que la DB funciona correctamente
	expiry := time.Now().Add(time.Hour)
	if err := s.SaveBan("1.2.3.4", "test", expiry); err != nil {
		t.Fatalf("SaveBan en archivo real: %v", err)
	}
	bans, err := s.LoadActiveBans()
	if err != nil {
		t.Fatal(err)
	}
	if len(bans) != 1 {
		t.Fatalf("esperado 1 ban, got %d", len(bans))
	}
}

func TestDeleteBan_IPNoExistente(t *testing.T) {
	s := openMemory(t)
	// Eliminar IP que no existe no debe retornar error
	if err := s.DeleteBan("9.9.9.9"); err != nil {
		t.Errorf("DeleteBan IP no existente: %v", err)
	}
}

func TestPruneSyncedEventsConMaxAge(t *testing.T) {
	s := openMemory(t)

	// Guardar 2 eventos y marcarlos como sincronizados
	for i := 0; i < 2; i++ {
		s.SaveEvent(event.Event{Type: event.AuthFailed, Timestamp: time.Now()})
	}
	events, _ := s.LoadUnsynced(100)
	ids := make([]int64, len(events))
	for i, e := range events {
		ids[i] = e.ID
	}
	s.MarkSynced(ids)

	// Con maxAge muy grande (1 hora), ningún evento debe ser podado
	n, err := s.PruneSyncedEvents(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("maxAge=1h: esperado 0 podados, got %d", n)
	}
}
