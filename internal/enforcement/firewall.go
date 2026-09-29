package enforcement

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"strings"
)

// fw abstracts the OS firewall so the Enforcer works on both RHEL (firewalld)
// and Ubuntu/Debian (ufw) without duplicating logic.
type fw interface {
	Block(ctx context.Context, ip string, banSeconds int) error
	Unblock(ctx context.Context, ip string) error
	ListBlockedIPs(ctx context.Context) ([]string, error)
}

// fwSetup lo implementan los backends que requieren inicialización
// (ej: firewalld-ipset crea el set y su binding la primera vez).
type fwSetup interface {
	Setup(ctx context.Context) error
}

// newFW returns the appropriate firewall backend.
// Unknown or empty backend defaults to firewalld.
func newFW(backend string) fw {
	switch backend {
	case "ufw":
		return &ufwFW{}
	case "firewalld-ipset":
		return &ipsetFW{}
	}
	return &firewalldFW{}
}

// ── firewalld ─────────────────────────────────────────────────────────────────

type firewalldFW struct{}

func (f *firewalldFW) Block(ctx context.Context, ip string, banSeconds int) error {
	for _, args := range buildFirewallCmds(ip, banSeconds) {
		cmd := newCmd(ctx, "firewall-cmd", args...)
		if out, err := cmd.CombinedOutput(); err != nil {
			// Según la versión, re-añadir una regla existente (conciliación,
			// par permanente ya presente) sale con error ALREADY_ENABLED.
			if strings.Contains(string(out), "ALREADY_ENABLED") {
				continue
			}
			return fmt.Errorf("firewall-cmd %v: %w — %s", args, err, bytes.TrimSpace(out))
		}
	}
	return nil
}

func (f *firewalldFW) Unblock(ctx context.Context, ip string) error {
	rule := fmt.Sprintf("rule family='ipv4' source address='%s' reject", ip)
	remove := fmt.Sprintf("--remove-rich-rule=%s", rule)
	// Ignore errors — rule may already be gone (expired timeout, manual removal).
	newCmd(ctx, "firewall-cmd", remove).Run()
	newCmd(ctx, "firewall-cmd", "--permanent", remove).Run()
	return nil
}

func (f *firewalldFW) ListBlockedIPs(ctx context.Context) ([]string, error) {
	out, err := newCmd(ctx, "firewall-cmd", "--list-rich-rules").Output()
	if err != nil {
		return nil, err
	}
	var ips []string
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		if ip := parseFirewallRule(scanner.Text()); ip != "" {
			ips = append(ips, ip)
		}
	}
	return ips, nil
}

// buildFirewallCmds devuelve los conjuntos de argumentos de firewall-cmd a ejecutar.
// ip acepta una dirección individual o un CIDR (las rich rules soportan ambos).
// Temporal: un solo comando con --timeout.
// Permanente: dos comandos — runtime (activo ahora) + permanent (sobrevive reload).
func buildFirewallCmds(ip string, banSeconds int) [][]string {
	rule := fmt.Sprintf("rule family='ipv4' source address='%s' reject", ip)
	richFlag := fmt.Sprintf("--add-rich-rule=%s", rule)
	if banSeconds > 0 {
		return [][]string{{richFlag, fmt.Sprintf("--timeout=%d", banSeconds)}}
	}
	return [][]string{
		{richFlag},
		{"--permanent", richFlag},
	}
}

// parseFirewallRule extrae la IP o el CIDR de una línea de `firewall-cmd --list-rich-rules`.
// Soporta comillas dobles y simples (el formato varía según la versión de firewalld).
// Retorna "" si la línea no corresponde a una regla SendGuard válida.
func parseFirewallRule(line string) string {
	for _, prefix := range []string{`address="`, `address='`} {
		idx := strings.Index(line, prefix)
		if idx == -1 {
			continue
		}
		rest := line[idx+len(prefix):]
		quote := prefix[len(prefix)-1]
		end := strings.IndexByte(rest, quote)
		if end == -1 {
			continue
		}
		if ip := rest[:end]; ValidBlockTarget(ip) {
			return ip
		}
	}
	return ""
}

// ── ufw ───────────────────────────────────────────────────────────────────────

type ufwFW struct{}

// Block agrega una regla de denegación AL INICIO de la lista (insert 1).
// ufw evalúa en orden y gana la primera coincidencia: un deny añadido al final
// (ufw deny a secas) queda detrás de los allow de los puertos de correo
// (25/465/587/993) y no bloquea nada en un mail server. ufw no soporta
// --timeout nativo; la expiración la gestiona el enforcer con runUnbanLoop.
func (f *ufwFW) Block(ctx context.Context, ip string, _ int) error {
	cmd := newCmd(ctx, "ufw", "insert", "1", "deny", "from", ip, "to", "any")
	out, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}
	// "Invalid position" = aún no hay reglas numeradas; solo ahí el append
	// simple es equivalente al insert.
	if !strings.Contains(string(out), "Invalid position") {
		return fmt.Errorf("ufw insert 1 deny %s: %w — %s", ip, err, bytes.TrimSpace(out))
	}
	cmd = newCmd(ctx, "ufw", "deny", "from", ip, "to", "any")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("ufw deny %s: %w — %s", ip, err, bytes.TrimSpace(out))
	}
	return nil
}

func (f *ufwFW) Unblock(ctx context.Context, ip string) error {
	cmd := newCmd(ctx, "ufw", "--force", "delete", "deny", "from", ip, "to", "any")
	out, err := cmd.CombinedOutput()
	if err != nil && !strings.Contains(string(out), "Could not delete") {
		return fmt.Errorf("ufw delete %s: %w — %s", ip, err, bytes.TrimSpace(out))
	}
	return nil
}

func (f *ufwFW) ListBlockedIPs(ctx context.Context) ([]string, error) {
	out, err := newCmd(ctx, "ufw", "status").Output()
	if err != nil {
		return nil, err
	}
	return parseUFWStatus(out), nil
}

// parseUFWStatus extrae las IPv4/CIDRs de las reglas de SendGuard en
// `ufw status`: las que crea Block ("deny from X to any"), que se listan como
//
//	Anywhere                   DENY        1.2.3.4
//
// `ufw status` a secas muestra la acción como "DENY"; con `verbose` o si la
// regla tiene dirección, "DENY IN". Se aceptan ambas (no "DENY OUT"). Solo
// cuentan las reglas con destino "Anywhere": un "deny 22 from X" del
// administrador no es un ban de SendGuard. Separado para tests sin ufw.
func parseUFWStatus(out []byte) []string {
	var ips []string
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		// Anywhere DENY [IN] <origen>
		if len(fields) < 3 || fields[0] != "Anywhere" || fields[1] != "DENY" {
			continue
		}
		src := fields[2]
		if src == "IN" && len(fields) >= 4 {
			src = fields[3]
		}
		if ValidBlockTarget(src) {
			ips = append(ips, src)
		}
	}
	return ips
}
