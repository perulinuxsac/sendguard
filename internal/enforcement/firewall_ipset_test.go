//go:build linux

package enforcement

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/perulinux/sendguard/internal/store"
)

// setupFakeFirewallCmd instala un firewall-cmd falso que registra cada
// invocación (una por línea) en un log y responde a las consultas según los
// argumentos dados. Retorna la ruta del log de invocaciones.
func setupFakeFirewallCmd(t *testing.T, script string) string {
	t.Helper()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "calls.log")
	full := "#!/bin/sh\necho \"$@\" >> " + logPath + "\n" + script
	if err := os.WriteFile(filepath.Join(dir, "firewall-cmd"), []byte(full), 0755); err != nil {
		t.Fatal(err)
	}
	prependPath(t, dir)
	return logPath
}

func readCalls(t *testing.T, logPath string) string {
	t.Helper()
	data, _ := os.ReadFile(logPath)
	return string(data)
}

func TestIpsetBlockTemporal(t *testing.T) {
	logPath := setupFakeFirewallCmd(t, "exit 0")

	f := &ipsetFW{}
	if err := f.Block(context.Background(), "1.2.3.4", 3600); err != nil {
		t.Fatalf("Block: %v", err)
	}

	calls := readCalls(t, logPath)
	if !strings.Contains(calls, "--ipset=sendguard --add-entry=1.2.3.4") {
		t.Errorf("debe agregar la entrada runtime: %q", calls)
	}
	if strings.Contains(calls, "--permanent") {
		t.Errorf("ban temporal no debe tocar la config permanente: %q", calls)
	}
}

func TestIpsetBlockPermanente(t *testing.T) {
	logPath := setupFakeFirewallCmd(t, "exit 0")

	f := &ipsetFW{}
	if err := f.Block(context.Background(), "200.25.47.0/24", 0); err != nil {
		t.Fatalf("Block CIDR permanente: %v", err)
	}

	calls := readCalls(t, logPath)
	if !strings.Contains(calls, "--ipset=sendguard --add-entry=200.25.47.0/24") {
		t.Errorf("falta la entrada runtime: %q", calls)
	}
	if !strings.Contains(calls, "--permanent --ipset=sendguard --add-entry=200.25.47.0/24") {
		t.Errorf("ban permanente debe escribirse también en permanente: %q", calls)
	}
}

func TestIpsetUnblock(t *testing.T) {
	logPath := setupFakeFirewallCmd(t, "exit 0")

	f := &ipsetFW{}
	if err := f.Unblock(context.Background(), "1.2.3.4"); err != nil {
		t.Fatalf("Unblock: %v", err)
	}

	calls := readCalls(t, logPath)
	if !strings.Contains(calls, "--ipset=sendguard --remove-entry=1.2.3.4") {
		t.Errorf("falta el remove runtime: %q", calls)
	}
	if !strings.Contains(calls, "--permanent --ipset=sendguard --remove-entry=1.2.3.4") {
		t.Errorf("falta el remove permanente: %q", calls)
	}
}

func TestIpsetSetupIdempotente(t *testing.T) {
	// El set y el binding ya existen: Setup no debe crear nada ni recargar.
	logPath := setupFakeFirewallCmd(t, `
case "$*" in
  *--get-ipsets*) echo "otroset sendguard" ;;
  *--list-sources*) echo "ipset:sendguard" ;;
esac
exit 0`)

	f := &ipsetFW{}
	if err := f.Setup(context.Background()); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	calls := readCalls(t, logPath)
	if strings.Contains(calls, "--reload") || strings.Contains(calls, "--new-ipset") {
		t.Errorf("Setup idempotente no debe crear ni recargar: %q", calls)
	}
}

func TestIpsetSetupCreaYRecarga(t *testing.T) {
	// Sin set: Setup debe crearlo, enlazarlo a la zona drop y recargar.
	logPath := setupFakeFirewallCmd(t, "exit 0")

	f := &ipsetFW{}
	if err := f.Setup(context.Background()); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	calls := readCalls(t, logPath)
	for _, want := range []string{
		"--permanent --new-ipset=sendguard --type=hash:net",
		"--permanent --zone=drop --add-source=ipset:sendguard",
		"--reload",
	} {
		if !strings.Contains(calls, want) {
			t.Errorf("Setup debe invocar %q; llamadas: %q", want, calls)
		}
	}
}

func TestParseIpsetEntries(t *testing.T) {
	out := []byte("1.2.3.4\n200.25.47.0/24\n\nbasura\n")
	entries := parseIpsetEntries(out)
	if len(entries) != 2 || entries[0] != "1.2.3.4" || entries[1] != "200.25.47.0/24" {
		t.Errorf("got %v, want [1.2.3.4 200.25.47.0/24]", entries)
	}
}

func TestUnbanExpiradoEliminaEntradaIpset(t *testing.T) {
	logPath := setupFakeFirewallCmd(t, "exit 0")

	e := New(Config{FirewallBackend: "firewalld-ipset", BanSeconds: 60})
	e.mu.Lock()
	e.blockedIPs["5.5.5.5"] = blockedIP{expiry: time.Now().Add(-time.Minute), module: "test"}
	e.mu.Unlock()

	e.unbanExpired(context.Background())

	calls := readCalls(t, logPath)
	if !strings.Contains(calls, "--ipset=sendguard --remove-entry=5.5.5.5") {
		t.Errorf("el ban expirado debe eliminarse del ipset: %q", calls)
	}
}

func TestResyncFirewallRepueblaIpset(t *testing.T) {
	logPath := setupFakeFirewallCmd(t, "exit 0")

	s, _ := store.Open(":memory:")
	defer s.Close()
	s.SaveBan("7.7.7.7", "manual", time.Now().Add(100*365*24*time.Hour)) // permanente
	s.SaveBan("8.8.8.8", "auth_failed", time.Now().Add(30*time.Minute))  // temporal vigente
	s.SaveBan("9.9.9.9", "auth_failed", time.Now().Add(-time.Hour))      // expirado

	e := New(Config{FirewallBackend: "firewalld-ipset", BanSeconds: 3600, Store: s})
	e.LoadExistingBans(context.Background())

	calls := readCalls(t, logPath)
	if !strings.Contains(calls, "--permanent --ipset=sendguard --add-entry=7.7.7.7") {
		t.Errorf("el ban permanente debe re-aplicarse en permanente: %q", calls)
	}
	if !strings.Contains(calls, "--ipset=sendguard --add-entry=8.8.8.8") {
		t.Errorf("el ban temporal vigente debe re-aplicarse: %q", calls)
	}
	if strings.Contains(calls, "add-entry=9.9.9.9") {
		t.Errorf("el ban expirado no debe re-aplicarse: %q", calls)
	}
}
