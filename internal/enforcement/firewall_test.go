//go:build linux

package enforcement

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/perulinux/sendguard/internal/detection"
)

// ── parseUFWStatus ────────────────────────────────────────────────────────────

func TestParseUFWStatusVacio(t *testing.T) {
	ips := parseUFWStatus([]byte("Status: inactive\n"))
	if len(ips) != 0 {
		t.Errorf("ufw inactivo: got %v, want []", ips)
	}
}

func TestParseUFWStatusUnaDeny(t *testing.T) {
	out := []byte(`Status: active

To                         Action      From
--                         ------      ----
Anywhere                   DENY IN     1.2.3.4
`)
	ips := parseUFWStatus(out)
	if len(ips) != 1 || ips[0] != "1.2.3.4" {
		t.Errorf("got %v, want [1.2.3.4]", ips)
	}
}

func TestParseUFWStatusMultiplesDeny(t *testing.T) {
	out := []byte(`Status: active

To                         Action      From
--                         ------      ----
Anywhere                   DENY IN     1.2.3.4
Anywhere                   DENY IN     5.6.7.8
Anywhere                   ALLOW IN    9.9.9.9
`)
	ips := parseUFWStatus(out)
	if len(ips) != 2 {
		t.Fatalf("got %d IPs, want 2: %v", len(ips), ips)
	}
	if ips[0] != "1.2.3.4" || ips[1] != "5.6.7.8" {
		t.Errorf("IPs: got %v", ips)
	}
}

func TestParseUFWStatusIgnoraAllow(t *testing.T) {
	out := []byte(`Status: active

Anywhere                   ALLOW IN    Anywhere
22/tcp                     ALLOW IN    Anywhere
`)
	ips := parseUFWStatus(out)
	if len(ips) != 0 {
		t.Errorf("ALLOW no debe extraer IPs: got %v", ips)
	}
}

func TestParseUFWStatusIgnoraIPv6(t *testing.T) {
	out := []byte(`Status: active

Anywhere                   DENY IN     1.2.3.4
Anywhere (v6)              DENY IN     ::1
`)
	ips := parseUFWStatus(out)
	// ::1 no pasa isValidIP (solo IPv4); 1.2.3.4 sí
	if len(ips) != 1 || ips[0] != "1.2.3.4" {
		t.Errorf("IPv6 debe ignorarse: got %v", ips)
	}
}

func TestParseUFWStatusCIDR(t *testing.T) {
	out := []byte(`Status: active

Anywhere                   DENY IN     200.25.47.0/24
Anywhere                   DENY IN     1.2.3.4
`)
	ips := parseUFWStatus(out)
	if len(ips) != 2 || ips[0] != "200.25.47.0/24" || ips[1] != "1.2.3.4" {
		t.Errorf("CIDR en ufw status: got %v, want [200.25.47.0/24 1.2.3.4]", ips)
	}
}

// ── ufw Block: insert 1 (la regla debe quedar ANTES de los allow) ─────────────

// setupLoggingBin crea un fake bin que registra sus argumentos en calls.log.
// extra se inserta antes del exit para simular comportamientos (fallos, output).
func setupLoggingBin(t *testing.T, name, extra string) (binDir, logFile string) {
	t.Helper()
	binDir = t.TempDir()
	logFile = filepath.Join(binDir, "calls.log")
	script := "#!/bin/sh\necho \"$@\" >> " + logFile + "\n" + extra + "exit 0\n"
	if err := os.WriteFile(filepath.Join(binDir, name), []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	return binDir, logFile
}

func TestUFWBlockInsertaAlInicio(t *testing.T) {
	binDir, logFile := setupLoggingBin(t, "ufw", "")
	prependPath(t, binDir)

	f := &ufwFW{}
	if err := f.Block(context.Background(), "1.2.3.4", 3600); err != nil {
		t.Fatalf("Block: %v", err)
	}
	data, _ := os.ReadFile(logFile)
	got := strings.TrimSpace(string(data))
	want := "insert 1 deny from 1.2.3.4 to any"
	if got != want {
		t.Errorf("ufw debe insertar al inicio: got %q, want %q", got, want)
	}
}

func TestUFWBlockFallbackSinReglasNumeradas(t *testing.T) {
	// Sin reglas numeradas, "insert 1" falla con "Invalid position" y el único
	// equivalente es el append simple.
	binDir := t.TempDir()
	logFile := filepath.Join(binDir, "calls.log")
	script := `#!/bin/sh
echo "$@" >> ` + logFile + `
if [ "$1" = "insert" ]; then
  echo "ERROR: Invalid position '1'"
  exit 1
fi
exit 0
`
	os.WriteFile(filepath.Join(binDir, "ufw"), []byte(script), 0755)
	prependPath(t, binDir)

	f := &ufwFW{}
	if err := f.Block(context.Background(), "5.6.7.8", 3600); err != nil {
		t.Fatalf("Block con fallback: %v", err)
	}
	data, _ := os.ReadFile(logFile)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 || lines[1] != "deny from 5.6.7.8 to any" {
		t.Errorf("esperado fallback a deny simple, got %v", lines)
	}
}

func TestUFWBlockPropagaOtrosErrores(t *testing.T) {
	binDir := t.TempDir()
	script := "#!/bin/sh\necho 'ERROR: something broke'\nexit 1\n"
	os.WriteFile(filepath.Join(binDir, "ufw"), []byte(script), 0755)
	prependPath(t, binDir)

	f := &ufwFW{}
	if err := f.Block(context.Background(), "5.6.7.8", 3600); err == nil {
		t.Error("un error distinto de Invalid position debe propagarse")
	}
}

// ── blockIP con backend ufw ───────────────────────────────────────────────────

func TestBlockIPConUFWBackend(t *testing.T) {
	binDir := setupFakeBin(t, "ufw")
	prependPath(t, binDir)

	e := New(Config{BanSeconds: 3600, FirewallBackend: "ufw"})
	e.blockIP(context.Background(), detection.Alert{
		IP:        "1.2.3.4",
		Module:    "authfailed",
		Action:    detection.ActionBlockIP,
		Timestamp: time.Now(),
	})

	if e.Stats().BlocksTotal != 1 {
		t.Errorf("BlocksTotal: got %d, want 1", e.Stats().BlocksTotal)
	}
	blocked := e.BlockedIPs()
	if len(blocked) != 1 || blocked[0].IP != "1.2.3.4" {
		t.Errorf("BlockedIPs: %v", blocked)
	}
}

func TestBlockIPConUFWDeduplicacion(t *testing.T) {
	binDir := setupFakeBin(t, "ufw")
	prependPath(t, binDir)

	e := New(Config{BanSeconds: 3600, FirewallBackend: "ufw"})
	alert := detection.Alert{IP: "2.2.2.2", Module: "test", Action: detection.ActionBlockIP, Timestamp: time.Now()}

	e.blockIP(context.Background(), alert)
	e.blockIP(context.Background(), alert)

	if e.Stats().BlocksTotal != 1 {
		t.Errorf("dedup ufw: BlocksTotal got %d, want 1", e.Stats().BlocksTotal)
	}
}

// ── loadBansFromFirewalld con backend ufw ─────────────────────────────────────

func TestLoadBansFromUFW(t *testing.T) {
	dir := t.TempDir()
	script := `#!/bin/sh
echo "Status: active"
echo ""
echo "To                         Action      From"
echo "--                         ------      ----"
echo "Anywhere                   DENY IN     3.3.3.3"
exit 0
`
	os.WriteFile(filepath.Join(dir, "ufw"), []byte(script), 0755)
	prependPath(t, dir)

	e := New(Config{BanSeconds: 3600, FirewallBackend: "ufw"})
	e.loadBansFromFirewalld(context.Background())

	blocked := e.BlockedIPs()
	if len(blocked) != 1 || blocked[0].IP != "3.3.3.3" {
		t.Errorf("loadBansFromUFW: got %v, want [3.3.3.3]", blocked)
	}
}

// ── unbanExpired ──────────────────────────────────────────────────────────────

func TestUnbanExpiredElimina(t *testing.T) {
	binDir := setupFakeBin(t, "ufw")
	prependPath(t, binDir)

	e := New(Config{BanSeconds: 1, FirewallBackend: "ufw"})

	e.mu.Lock()
	e.blockedIPs["9.9.9.9"] = blockedIP{expiry: time.Now().Add(-time.Second), module: "test"}
	e.blockedIPs["8.8.8.8"] = blockedIP{expiry: time.Now().Add(time.Hour), module: "test"}
	e.mu.Unlock()

	e.unbanExpired(context.Background())

	blocked := e.BlockedIPs()
	if len(blocked) != 1 || blocked[0].IP != "8.8.8.8" {
		t.Errorf("unbanExpired: esperado solo 8.8.8.8 vigente, got %v", blocked)
	}
}

func TestUnbanExpiredNadaExpirado(t *testing.T) {
	binDir := setupFakeBin(t, "ufw")
	prependPath(t, binDir)

	e := New(Config{BanSeconds: 3600, FirewallBackend: "ufw"})
	e.mu.Lock()
	e.blockedIPs["1.1.1.1"] = blockedIP{expiry: time.Now().Add(time.Hour), module: "test"}
	e.mu.Unlock()

	e.unbanExpired(context.Background())

	if len(e.BlockedIPs()) != 1 {
		t.Error("sin expirados: no debe modificar el mapa")
	}
}

// ── blockIP — guard de IPs privadas/locales ───────────────────────────────────

func TestBlockIPPrivadaOmitida(t *testing.T) {
	binDir := setupFakeBin(t, "ufw")
	prependPath(t, binDir)

	e := New(Config{BanSeconds: 3600, FirewallBackend: "ufw"})
	for _, ip := range []string{"127.0.0.1", "10.1.2.3", "172.16.1.50", "192.168.0.10", "169.254.1.1"} {
		e.blockIP(context.Background(), detection.Alert{
			IP: ip, Module: "test", Action: detection.ActionBlockIP, Timestamp: time.Now(),
		})
	}

	if e.Stats().BlocksTotal != 0 {
		t.Errorf("IPs privadas no deben bloquearse: BlocksTotal got %d, want 0", e.Stats().BlocksTotal)
	}
	if len(e.BlockedIPs()) != 0 {
		t.Errorf("IPs privadas no deben registrarse como bloqueadas: %v", e.BlockedIPs())
	}
}

func TestBlockManualIPPrivadaRetornaError(t *testing.T) {
	e := New(Config{BanSeconds: 3600, FirewallBackend: "ufw"})
	if err := e.Block(context.Background(), "172.16.1.50", 0); err == nil {
		t.Error("Block manual de IP privada debe retornar error")
	}
	if err := e.Block(context.Background(), "192.168.1.1", -1); err == nil {
		t.Error("Block manual permanente de IP privada debe retornar error")
	}
}
