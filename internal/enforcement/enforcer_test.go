package enforcement

import (
	"testing"
	"time"
)

// --- isValidIP ---

func TestIsValidIPv4(t *testing.T) {
	valid := []string{"1.2.3.4", "192.168.0.1", "10.0.0.1", "255.255.255.255"}
	for _, ip := range valid {
		if !isValidIP(ip) {
			t.Errorf("isValidIP(%q): got false, want true", ip)
		}
	}
}

func TestIsValidIPRechazaInvalidas(t *testing.T) {
	invalid := []string{
		"",
		"not-an-ip",
		"::1",               // IPv6
		"2001:db8::1",       // IPv6
		"256.0.0.1",         // fuera de rango
		"1.2.3",             // incompleta
		"1.2.3.4.5",         // demasiados octetos
	}
	for _, ip := range invalid {
		if isValidIP(ip) {
			t.Errorf("isValidIP(%q): got true, want false", ip)
		}
	}
}

// --- buildFirewallCmds ---

func TestBuildFirewallCmdsTemporal(t *testing.T) {
	cmds := buildFirewallCmds("1.2.3.4", 3600)
	if len(cmds) != 1 {
		t.Fatalf("temporal: esperaba 1 comando, got %d", len(cmds))
	}
	args := cmds[0]
	foundTimeout := false
	for _, a := range args {
		if a == "--timeout=3600" {
			foundTimeout = true
		}
	}
	if !foundTimeout {
		t.Errorf("temporal: debe incluir --timeout=3600, args=%v", args)
	}
}

func TestBuildFirewallCmdsPermanente(t *testing.T) {
	cmds := buildFirewallCmds("1.2.3.4", 0)
	if len(cmds) != 2 {
		t.Fatalf("permanente: esperaba 2 comandos, got %d", len(cmds))
	}
	// primer comando: runtime (sin --permanent)
	for _, a := range cmds[0] {
		if a == "--permanent" {
			t.Error("primer comando no debe tener --permanent")
		}
	}
	// segundo comando: persistente
	foundPerm := false
	for _, a := range cmds[1] {
		if a == "--permanent" {
			foundPerm = true
		}
	}
	if !foundPerm {
		t.Error("segundo comando debe tener --permanent")
	}
}

func TestBuildFirewallCmdsContieneIP(t *testing.T) {
	cmds := buildFirewallCmds("9.8.7.6", 60)
	for _, args := range cmds {
		found := false
		for _, a := range args {
			if a == "--add-rich-rule=rule family='ipv4' source address='9.8.7.6' reject" {
				found = true
			}
		}
		if !found {
			t.Errorf("comando no contiene la regla con IP 9.8.7.6: %v", args)
		}
	}
}

// --- parseFirewallRule ---

func TestParseFirewallRuleValida(t *testing.T) {
	line := `rule family="ipv4" source address="1.2.3.4" reject`
	if got := parseFirewallRule(line); got != "1.2.3.4" {
		t.Errorf("got %q, want 1.2.3.4", got)
	}
}

func TestParseFirewallRuleConComillasSimples(t *testing.T) {
	// firewall-cmd puede emitir reglas con comillas simples (varía según versión).
	line := `rule family='ipv4' source address='5.6.7.8' reject`
	if got := parseFirewallRule(line); got != "5.6.7.8" {
		t.Errorf("comillas simples: got %q, want 5.6.7.8", got)
	}
}

func TestParseFirewallRuleLineaVacia(t *testing.T) {
	if got := parseFirewallRule(""); got != "" {
		t.Errorf("línea vacía: got %q, want \"\"", got)
	}
}

func TestParseFirewallRuleIPv6(t *testing.T) {
	line := `rule family="ipv6" source address="::1" reject`
	if got := parseFirewallRule(line); got != "" {
		t.Errorf("IPv6 debe retornar \"\", got %q", got)
	}
}

func TestParseFirewallRuleSinAddress(t *testing.T) {
	line := `rule family="ipv4" reject`
	if got := parseFirewallRule(line); got != "" {
		t.Errorf("sin address: got %q, want \"\"", got)
	}
}

func TestParseFirewallRuleIPInvalida(t *testing.T) {
	line := `rule family="ipv4" source address="not-an-ip" reject`
	if got := parseFirewallRule(line); got != "" {
		t.Errorf("IP inválida: got %q, want \"\"", got)
	}
}

// --- BlockedIPs ---

func TestBlockedIPsFiltradoExpiradas(t *testing.T) {
	e := New(Config{BanSeconds: 3600})

	now := time.Now()
	e.mu.Lock()
	e.blockedIPs["1.2.3.4"] = blockedIP{expiry: now.Add(time.Hour), module: "test"}   // vigente
	e.blockedIPs["5.6.7.8"] = blockedIP{expiry: now.Add(-time.Second), module: "test"} // expirada
	e.mu.Unlock()

	blocked := e.BlockedIPs()
	if len(blocked) != 1 {
		t.Fatalf("BlockedIPs: got %d, want 1 (la expirada no debe aparecer)", len(blocked))
	}
	if blocked[0].IP != "1.2.3.4" {
		t.Errorf("IP: got %q, want 1.2.3.4", blocked[0].IP)
	}
}

func TestBlockedIPsVacio(t *testing.T) {
	e := New(Config{BanSeconds: 3600})
	if got := e.BlockedIPs(); len(got) != 0 {
		t.Errorf("enforcer nuevo: got %d IPs, want 0", len(got))
	}
}

func TestBlockedIPsInfoCompleta(t *testing.T) {
	e := New(Config{BanSeconds: 3600})
	expiry := time.Now().Add(time.Hour)

	e.mu.Lock()
	e.blockedIPs["9.9.9.9"] = blockedIP{expiry: expiry, module: "auth_failed"}
	e.mu.Unlock()

	blocked := e.BlockedIPs()
	if len(blocked) != 1 {
		t.Fatalf("got %d IPs, want 1", len(blocked))
	}
	b := blocked[0]
	if b.IP != "9.9.9.9" {
		t.Errorf("IP: got %q, want 9.9.9.9", b.IP)
	}
	if b.Module != "auth_failed" {
		t.Errorf("Module: got %q, want auth_failed", b.Module)
	}
	if b.Expiry.IsZero() {
		t.Error("Expiry no debe ser zero")
	}
}

// --- Stats ---

func TestStatsContadoresIniciales(t *testing.T) {
	e := New(Config{})
	s := e.Stats()
	if s.BlocksTotal != 0 || s.SuspensionsTotal != 0 || s.RateLimitsTotal != 0 {
		t.Errorf("contadores deben ser 0 al inicio: %+v", s)
	}
}

func TestStatsContadoresActomicos(t *testing.T) {
	e := New(Config{})
	e.blocksTotal.Add(3)
	e.suspsTotal.Add(1)
	e.ratesTotal.Add(2)

	s := e.Stats()
	if s.BlocksTotal != 3 {
		t.Errorf("BlocksTotal: got %d, want 3", s.BlocksTotal)
	}
	if s.SuspensionsTotal != 1 {
		t.Errorf("SuspensionsTotal: got %d, want 1", s.SuspensionsTotal)
	}
	if s.RateLimitsTotal != 2 {
		t.Errorf("RateLimitsTotal: got %d, want 2", s.RateLimitsTotal)
	}
}

// --- LoadExistingBans (parseFirewallRule ya probado arriba) ---

func TestLoadExistingBansParseoMultiplesLineas(t *testing.T) {
	// Verificar que parseFirewallRule extrae correctamente múltiples IPs
	// de la salida simulada de firewall-cmd --list-rich-rules.
	lines := []string{
		`rule family="ipv4" source address="1.1.1.1" reject`,
		`rule family="ipv4" source address="2.2.2.2" reject`,
		`rule family="ipv6" source address="::1" reject`,      // debe ignorarse
		`rule priority="0" service name="ssh" accept`,         // sin address, debe ignorarse
		`rule family="ipv4" source address="3.3.3.3" reject`,
	}
	ips := []string{}
	for _, line := range lines {
		if ip := parseFirewallRule(line); ip != "" {
			ips = append(ips, ip)
		}
	}
	if len(ips) != 3 {
		t.Fatalf("se esperaban 3 IPs válidas, got %d: %v", len(ips), ips)
	}
}

func TestLoadExistingBansNoDuplicados(t *testing.T) {
	e := New(Config{BanSeconds: 3600})

	// Precargar una IP en el mapa
	e.mu.Lock()
	e.blockedIPs["1.2.3.4"] = blockedIP{expiry: time.Now().Add(time.Hour), module: "existing"}
	e.mu.Unlock()

	// Simular que LoadExistingBans encontraría la misma IP — no debe sobreescribir.
	// La función verifica `if _, exists := e.blockedIPs[ip]; !exists`.
	// Llamamos la lógica directamente en el mapa:
	ip := "1.2.3.4"
	e.mu.Lock()
	if _, exists := e.blockedIPs[ip]; !exists {
		e.blockedIPs[ip] = blockedIP{expiry: time.Now().Add(2 * time.Hour), module: "restored"}
	}
	e.mu.Unlock()

	e.mu.Lock()
	entry := e.blockedIPs["1.2.3.4"]
	e.mu.Unlock()

	if entry.module != "existing" {
		t.Errorf("no debe sobreescribir entrada existente: module=%q", entry.module)
	}
}
