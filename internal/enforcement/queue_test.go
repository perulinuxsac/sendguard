//go:build linux

package enforcement

import (
	"context"
	"os"
	"path/filepath"

	"testing"
)

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
