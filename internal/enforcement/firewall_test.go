//go:build linux

package enforcement

import (
	"context"
	"os"
	"path/filepath"
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
