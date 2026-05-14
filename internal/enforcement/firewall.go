package enforcement

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// fw abstracts the OS firewall so the Enforcer works on both RHEL (firewalld)
// and Ubuntu/Debian (ufw) without duplicating logic.
type fw interface {
	Block(ctx context.Context, ip string, banSeconds int) error
	Unblock(ctx context.Context, ip string) error
	ListBlockedIPs(ctx context.Context) ([]string, error)
}

// newFW returns the appropriate firewall backend.
// Unknown or empty backend defaults to firewalld.
func newFW(backend string) fw {
	if backend == "ufw" {
		return &ufwFW{}
	}
	return &firewalldFW{}
}

// ── firewalld ─────────────────────────────────────────────────────────────────

type firewalldFW struct{}

func (f *firewalldFW) Block(ctx context.Context, ip string, banSeconds int) error {
	for _, args := range buildFirewallCmds(ip, banSeconds) {
		cmd := exec.CommandContext(ctx, "firewall-cmd", args...)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("firewall-cmd %v: %w — %s", args, err, bytes.TrimSpace(out))
		}
	}
	return nil
}

func (f *firewalldFW) Unblock(ctx context.Context, ip string) error {
	rule := fmt.Sprintf("rule family='ipv4' source address='%s' reject", ip)
	remove := fmt.Sprintf("--remove-rich-rule=%s", rule)
	// Ignore errors — rule may already be gone (expired timeout, manual removal).
	exec.CommandContext(ctx, "firewall-cmd", remove).Run()
	exec.CommandContext(ctx, "firewall-cmd", "--permanent", remove).Run()
	return nil
}

func (f *firewalldFW) ListBlockedIPs(ctx context.Context) ([]string, error) {
	out, err := exec.CommandContext(ctx, "firewall-cmd", "--list-rich-rules").Output()
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

// parseFirewallRule extrae la IP de una línea de `firewall-cmd --list-rich-rules`.
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
		if ip := rest[:end]; isValidIP(ip) {
			return ip
		}
	}
	return ""
}

// ── ufw ───────────────────────────────────────────────────────────────────────

type ufwFW struct{}

// Block agrega una regla de denegación. ufw no soporta --timeout nativo;
// la expiración la gestiona el enforcer con runUnbanLoop.
func (f *ufwFW) Block(ctx context.Context, ip string, _ int) error {
	cmd := exec.CommandContext(ctx, "ufw", "deny", "from", ip, "to", "any")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("ufw deny %s: %w — %s", ip, err, bytes.TrimSpace(out))
	}
	return nil
}

func (f *ufwFW) Unblock(ctx context.Context, ip string) error {
	cmd := exec.CommandContext(ctx, "ufw", "--force", "delete", "deny", "from", ip, "to", "any")
	out, err := cmd.CombinedOutput()
	if err != nil && !strings.Contains(string(out), "Could not delete") {
		return fmt.Errorf("ufw delete %s: %w — %s", ip, err, bytes.TrimSpace(out))
	}
	return nil
}

func (f *ufwFW) ListBlockedIPs(ctx context.Context) ([]string, error) {
	out, err := exec.CommandContext(ctx, "ufw", "status").Output()
	if err != nil {
		return nil, err
	}
	return parseUFWStatus(out), nil
}

// parseUFWStatus extrae IPv4 de líneas "DENY IN" de `ufw status`.
// Separado para facilitar tests sin necesitar el binario ufw.
func parseUFWStatus(out []byte) []string {
	var ips []string
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, "DENY IN") {
			continue
		}
		// Línea: "Anywhere   DENY IN   1.2.3.4"
		// Tomar el último campo que sea una IPv4 válida.
		fields := strings.Fields(line)
		for _, f := range fields {
			if isValidIP(f) {
				ips = append(ips, f)
				break
			}
		}
	}
	return ips
}
