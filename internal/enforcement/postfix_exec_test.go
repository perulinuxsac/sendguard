//go:build linux

package enforcement

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ── rateLimit ─────────────────────────────────────────────────────────────────

func TestRateLimitEscribeAccessFileYLlamaPostmap(t *testing.T) {
	sbinDir := setupFakeBin(t, "postmap")
	confDir := t.TempDir()

	err := rateLimit(context.Background(), "user@domain.com", 0, sbinDir, confDir)
	if err != nil {
		t.Fatalf("rateLimit: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(confDir, "sendguard_access"))
	if err != nil {
		t.Fatalf("access file no creado: %v", err)
	}
	if !strings.Contains(string(data), "user@domain.com") {
		t.Errorf("access file no contiene la cuenta: %q", string(data))
	}
	if !strings.Contains(string(data), "REJECT") {
		t.Errorf("access file debe tener acción REJECT: %q", string(data))
	}
}

func TestRateLimitSinPostmap(t *testing.T) {
	sbinDir := t.TempDir() // sin postmap → debe retornar error
	confDir := t.TempDir()

	err := rateLimit(context.Background(), "user@domain.com", 0, sbinDir, confDir)
	if err == nil {
		t.Error("sin postmap debe retornar error")
	}
}

func TestRateLimitAccessFileNoEscribible(t *testing.T) {
	sbinDir := setupFakeBin(t, "postmap")
	confDir := "/no/existe/directorio/que/no/puede/crearse"

	err := rateLimit(context.Background(), "user@domain.com", 0, sbinDir, confDir)
	if err == nil {
		t.Error("directorio inaccesible debe retornar error")
	}
}

// ── removeRateLimit ──────────────────────────────────────────────────────────

func TestRemoveRateLimitEliminalaCuenta(t *testing.T) {
	sbinDir := setupFakeBin(t, "postmap")
	confDir := t.TempDir()

	accessFile := filepath.Join(confDir, "sendguard_access")
	content := "user@domain.com REJECT SendGuard\nother@domain.com REJECT SendGuard\n"
	os.WriteFile(accessFile, []byte(content), 0644)

	removeRateLimit("user@domain.com", sbinDir, confDir)

	data, _ := os.ReadFile(accessFile)
	if strings.Contains(string(data), "user@domain.com") {
		t.Error("removeRateLimit debe eliminar la línea de la cuenta")
	}
	if !strings.Contains(string(data), "other@domain.com") {
		t.Error("removeRateLimit no debe eliminar otras cuentas")
	}
}

func TestRemoveRateLimitArchivoNoExiste(t *testing.T) {
	sbinDir := setupFakeBin(t, "postmap")
	confDir := t.TempDir()
	// No debe panic cuando el access file no existe
	removeRateLimit("user@domain.com", sbinDir, confDir)
}

// ── purgeQueueDomain ─────────────────────────────────────────────────────────

func TestPurgeQueueDomainSinMensajes(t *testing.T) {
	sbinDir := t.TempDir()
	confDir := t.TempDir()

	os.WriteFile(filepath.Join(sbinDir, "postqueue"),
		[]byte("#!/bin/sh\necho 'Mail queue is empty'\nexit 0\n"), 0755)

	n, err := purgeQueueDomain(context.Background(), "example.com", sbinDir, confDir)
	if err != nil {
		t.Fatalf("purgeQueueDomain: %v", err)
	}
	if n != 0 {
		t.Errorf("cola vacía: esperado 0 eliminados, got %d", n)
	}
}

func TestPurgeQueueDomainConMensajes(t *testing.T) {
	sbinDir := t.TempDir()
	confDir := t.TempDir()

	postqueueOut := `-Queue ID-  --Size-- ----Arrival Time---- -Sender/Recipient-------
A1B2C3D4E*     1234 Sat May 11 10:00:00  sender@source.com
                                         user@target.com

`
	postqueueScript := "#!/bin/sh\ncat << 'ENDOFQUEUE'\n" + postqueueOut + "ENDOFQUEUE\nexit 0\n"
	os.WriteFile(filepath.Join(sbinDir, "postqueue"), []byte(postqueueScript), 0755)
	os.WriteFile(filepath.Join(sbinDir, "postsuper"), []byte("#!/bin/sh\nexit 0\n"), 0755)

	n, err := purgeQueueDomain(context.Background(), "target.com", sbinDir, confDir)
	if err != nil {
		t.Fatalf("purgeQueueDomain: %v", err)
	}
	if n != 1 {
		t.Errorf("esperado 1 mensaje eliminado, got %d", n)
	}
}

func TestPurgeQueueDomainPostqueueError(t *testing.T) {
	sbinDir := t.TempDir()
	confDir := t.TempDir()

	// postqueue que falla
	os.WriteFile(filepath.Join(sbinDir, "postqueue"),
		[]byte("#!/bin/sh\nexit 1\n"), 0755)

	_, err := purgeQueueDomain(context.Background(), "example.com", sbinDir, confDir)
	if err == nil {
		t.Error("postqueue con exit 1 debe retornar error")
	}
}

// ── ListQueue ─────────────────────────────────────────────────────────────────

func TestListQueueVacia(t *testing.T) {
	sbinDir := t.TempDir()
	confDir := t.TempDir()
	os.WriteFile(filepath.Join(sbinDir, "postqueue"),
		[]byte("#!/bin/sh\necho 'Mail queue is empty'\nexit 0\n"), 0755)

	entries, err := ListQueue(context.Background(), sbinDir, confDir)
	if err != nil {
		t.Fatalf("ListQueue: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("cola vacía: esperado 0 entradas, got %d", len(entries))
	}
}

func TestListQueueConMensajes(t *testing.T) {
	sbinDir := t.TempDir()
	confDir := t.TempDir()

	postqueueOut := `-Queue ID-  --Size-- ----Arrival Time---- -Sender/Recipient-------
A1B2C3D4E*     1234 Sat May 11 10:00:00  sender@source.com
                                         user@target.com

`
	script := "#!/bin/sh\ncat << 'ENDOFQUEUE'\n" + postqueueOut + "ENDOFQUEUE\nexit 0\n"
	os.WriteFile(filepath.Join(sbinDir, "postqueue"), []byte(script), 0755)

	entries, err := ListQueue(context.Background(), sbinDir, confDir)
	if err != nil {
		t.Fatalf("ListQueue: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("esperado 1 entrada, got %d", len(entries))
	}
	if entries[0].Sender != "sender@source.com" {
		t.Errorf("Sender: got %q, want sender@source.com", entries[0].Sender)
	}
	if len(entries[0].Recipients) != 1 || entries[0].Recipients[0] != "user@target.com" {
		t.Errorf("Recipients: got %v", entries[0].Recipients)
	}
}

func TestListQueuePostqueueError(t *testing.T) {
	sbinDir := t.TempDir()
	confDir := t.TempDir()
	os.WriteFile(filepath.Join(sbinDir, "postqueue"),
		[]byte("#!/bin/sh\nexit 1\n"), 0755)

	_, err := ListQueue(context.Background(), sbinDir, confDir)
	if err == nil {
		t.Error("postqueue con exit 1 debe retornar error")
	}
}

// ── parseQueueFull ────────────────────────────────────────────────────────────

func TestParseQueueFullVarios(t *testing.T) {
	input := `-Queue ID-  --Size-- ----Arrival Time---- -Sender/Recipient-------
AAA111*      500 Mon May 12 08:00:00  a@src.com
                                      b@dst.com
                                      c@dst.com

BBB222!     1000 Mon May 12 09:00:00  x@src.com
                                      y@dst.com

`
	entries := parseQueueFull([]byte(input))
	if len(entries) != 2 {
		t.Fatalf("esperado 2 entradas, got %d", len(entries))
	}
	if entries[0].ID != "AAA111" {
		t.Errorf("ID[0]: got %q, want AAA111", entries[0].ID)
	}
	if len(entries[0].Recipients) != 2 {
		t.Errorf("Recipients[0]: got %d, want 2", len(entries[0].Recipients))
	}
	if entries[1].ID != "BBB222" {
		t.Errorf("ID[1]: got %q, want BBB222", entries[1].ID)
	}
}
