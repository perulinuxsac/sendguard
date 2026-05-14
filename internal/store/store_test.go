package store

import (
	"testing"
	"time"

	"github.com/perulinux/sendguard/internal/event"
)

// openMemory abre una base de datos SQLite en memoria para tests.
func openMemory(t *testing.T) *Store {
	t.Helper()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatalf("Open(:memory:): %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// ── Bans ─────────────────────────────────────────────────────────────────────

func TestSaveAndLoadBan(t *testing.T) {
	s := openMemory(t)

	expiry := time.Now().Add(time.Hour).Truncate(time.Second)
	if err := s.SaveBan("1.2.3.4", "authfailed", expiry); err != nil {
		t.Fatalf("SaveBan: %v", err)
	}

	bans, err := s.LoadActiveBans()
	if err != nil {
		t.Fatalf("LoadActiveBans: %v", err)
	}
	if len(bans) != 1 {
		t.Fatalf("esperado 1 ban, got %d", len(bans))
	}
	if bans[0].IP != "1.2.3.4" {
		t.Errorf("IP: got %q, want %q", bans[0].IP, "1.2.3.4")
	}
	if bans[0].Module != "authfailed" {
		t.Errorf("Module: got %q, want %q", bans[0].Module, "authfailed")
	}
	if !bans[0].ExpiresAt.Equal(expiry) {
		t.Errorf("ExpiresAt: got %v, want %v", bans[0].ExpiresAt, expiry)
	}
}

func TestSaveBan_Replace(t *testing.T) {
	s := openMemory(t)

	expiry1 := time.Now().Add(time.Hour).Truncate(time.Second)
	expiry2 := time.Now().Add(2 * time.Hour).Truncate(time.Second)

	if err := s.SaveBan("1.2.3.4", "authfailed", expiry1); err != nil {
		t.Fatal(err)
	}
	// Reemplazar el ban con nueva expiración (IP ya baneada, módulo distinto)
	if err := s.SaveBan("1.2.3.4", "numbermessages", expiry2); err != nil {
		t.Fatal(err)
	}

	bans, err := s.LoadActiveBans()
	if err != nil {
		t.Fatal(err)
	}
	if len(bans) != 1 {
		t.Fatalf("esperado 1 ban tras replace, got %d", len(bans))
	}
	if bans[0].Module != "numbermessages" {
		t.Errorf("Module después de replace: got %q", bans[0].Module)
	}
}

func TestDeleteBan(t *testing.T) {
	s := openMemory(t)

	expiry := time.Now().Add(time.Hour)
	if err := s.SaveBan("1.2.3.4", "authfailed", expiry); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteBan("1.2.3.4"); err != nil {
		t.Fatalf("DeleteBan: %v", err)
	}

	bans, err := s.LoadActiveBans()
	if err != nil {
		t.Fatal(err)
	}
	if len(bans) != 0 {
		t.Fatalf("esperado 0 bans tras delete, got %d", len(bans))
	}
}

func TestLoadActiveBans_ExcludesExpired(t *testing.T) {
	s := openMemory(t)

	// Ban expirado (en el pasado)
	past := time.Now().Add(-time.Hour)
	if err := s.SaveBan("1.2.3.4", "authfailed", past); err != nil {
		t.Fatal(err)
	}
	// Ban activo (en el futuro)
	future := time.Now().Add(time.Hour)
	if err := s.SaveBan("5.6.7.8", "numbermessages", future); err != nil {
		t.Fatal(err)
	}

	bans, err := s.LoadActiveBans()
	if err != nil {
		t.Fatal(err)
	}
	if len(bans) != 1 {
		t.Fatalf("esperado 1 ban activo, got %d", len(bans))
	}
	if bans[0].IP != "5.6.7.8" {
		t.Errorf("IP activo: got %q, want %q", bans[0].IP, "5.6.7.8")
	}
}

func TestPruneExpiredBans(t *testing.T) {
	s := openMemory(t)

	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(time.Hour)

	if err := s.SaveBan("1.1.1.1", "authfailed", past); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveBan("2.2.2.2", "authfailed", future); err != nil {
		t.Fatal(err)
	}

	n, err := s.PruneExpiredBans()
	if err != nil {
		t.Fatalf("PruneExpiredBans: %v", err)
	}
	if n != 1 {
		t.Errorf("esperado 1 ban podado, got %d", n)
	}

	bans, _ := s.LoadActiveBans()
	if len(bans) != 1 || bans[0].IP != "2.2.2.2" {
		t.Errorf("ban activo incorrecto tras prune: %+v", bans)
	}
}

func TestLoadActiveBans_PermanentBan(t *testing.T) {
	s := openMemory(t)

	// Ban permanente: expiry = 100 años en el futuro
	permanent := time.Now().Add(100 * 365 * 24 * time.Hour)
	if err := s.SaveBan("9.9.9.9", "manual", permanent); err != nil {
		t.Fatal(err)
	}

	bans, err := s.LoadActiveBans()
	if err != nil {
		t.Fatal(err)
	}
	if len(bans) != 1 {
		t.Fatalf("ban permanente no encontrado")
	}
}

// ── Eventos pendientes (StoreAndForward) ─────────────────────────────────────

func TestSaveAndLoadEvents(t *testing.T) {
	s := openMemory(t)

	ev := event.Event{
		Type:      event.AuthFailed,
		Account:   "user@domain.com",
		IP:        "1.2.3.4",
		Domain:    "domain.com",
		Server:    "mail1",
		Country:   "PE",
		Timestamp: time.Now().Truncate(time.Second),
		Raw:       "May 11 10:23:45 mail1 postfix/smtpd[1234]: warning",
	}

	if err := s.SaveEvent(ev); err != nil {
		t.Fatalf("SaveEvent: %v", err)
	}

	events, err := s.LoadUnsynced(100)
	if err != nil {
		t.Fatalf("LoadUnsynced: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("esperado 1 evento, got %d", len(events))
	}

	got := events[0].Event
	if got.Type != ev.Type {
		t.Errorf("Type: got %q, want %q", got.Type, ev.Type)
	}
	if got.Account != ev.Account {
		t.Errorf("Account: got %q, want %q", got.Account, ev.Account)
	}
	if got.IP != ev.IP {
		t.Errorf("IP: got %q, want %q", got.IP, ev.IP)
	}
	if got.Country != ev.Country {
		t.Errorf("Country: got %q, want %q", got.Country, ev.Country)
	}
}

func TestMarkSynced(t *testing.T) {
	s := openMemory(t)

	for i := 0; i < 3; i++ {
		if err := s.SaveEvent(event.Event{
			Type:      event.MessageSent,
			Timestamp: time.Now(),
		}); err != nil {
			t.Fatal(err)
		}
	}

	events, _ := s.LoadUnsynced(100)
	if len(events) != 3 {
		t.Fatalf("esperado 3 eventos, got %d", len(events))
	}

	ids := []int64{events[0].ID, events[1].ID}
	if err := s.MarkSynced(ids); err != nil {
		t.Fatalf("MarkSynced: %v", err)
	}

	pending, _ := s.LoadUnsynced(100)
	if len(pending) != 1 {
		t.Fatalf("esperado 1 evento pendiente, got %d", len(pending))
	}
	if pending[0].ID != events[2].ID {
		t.Errorf("ID pendiente: got %d, want %d", pending[0].ID, events[2].ID)
	}
}

func TestMarkSynced_Empty(t *testing.T) {
	s := openMemory(t)
	// No debe fallar con slice vacío
	if err := s.MarkSynced(nil); err != nil {
		t.Errorf("MarkSynced(nil): %v", err)
	}
	if err := s.MarkSynced([]int64{}); err != nil {
		t.Errorf("MarkSynced([]): %v", err)
	}
}

func TestLoadUnsynced_Limit(t *testing.T) {
	s := openMemory(t)

	for i := 0; i < 10; i++ {
		s.SaveEvent(event.Event{Type: event.AuthFailed, Timestamp: time.Now()})
	}

	events, err := s.LoadUnsynced(5)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 5 {
		t.Errorf("LoadUnsynced limit=5: got %d", len(events))
	}
}

func TestPruneSyncedEvents(t *testing.T) {
	s := openMemory(t)

	// Guardar y marcar 2 eventos como sincronizados
	for i := 0; i < 2; i++ {
		s.SaveEvent(event.Event{Type: event.MessageSent, Timestamp: time.Now()})
	}
	events, _ := s.LoadUnsynced(100)
	ids := make([]int64, len(events))
	for i, e := range events {
		ids[i] = e.ID
	}
	s.MarkSynced(ids)

	// Guardar 1 evento sin sincronizar
	s.SaveEvent(event.Event{Type: event.AuthFailed, Timestamp: time.Now()})

	// Prune con maxAge=0 (elimina todos los sincronizados creados "ahora")
	n, err := s.PruneSyncedEvents(0)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("PruneSyncedEvents: esperado 2, got %d", n)
	}

	// El evento no sincronizado debe seguir ahí
	pending, _ := s.LoadUnsynced(100)
	if len(pending) != 1 {
		t.Errorf("evento no sincronizado: esperado 1, got %d", len(pending))
	}
}
