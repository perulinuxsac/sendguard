package enforcement

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
)

// ── firewalld + ipset ─────────────────────────────────────────────────────────
//
// Backend "firewalld-ipset": en lugar de una rich rule por IP (que degrada a
// firewalld cuando se acumulan miles — cada firewall-cmd tardaba ~7s en
// webmail con 16k reglas), mantiene UN único set hash:net enlazado a la zona
// drop. Altas y bajas de entradas son O(1) y soporta IPs y CIDRs nativamente.
//
// Persistencia: las entradas temporales son solo runtime (la expiración la
// gestiona el enforcer con runUnbanLoop, igual que con ufw); las permanentes
// se escriben también en la config permanente de firewalld. Tras un reload o
// reboot, el enforcer repuebla el set desde SQLite (resyncFirewall).
//
// Nota de semántica: la zona drop DESCARTA el tráfico (DROP) en lugar del
// REJECT de las rich rules. Para IPs atacantes es incluso preferible (no se
// les confirma que el host existe). Se usa el binding de zona y no una rich
// rule "source ipset=" porque la zona funciona también en firewalld 0.6
// (CentOS 7), donde la rich rule con ipset no está soportada.

const ipsetName = "sendguard"

type ipsetFW struct{}

// Setup garantiza que el ipset existe y está enlazado a la zona drop.
// Idempotente: si todo está en su sitio no toca nada (ni recarga firewalld).
// La primera vez crea el set y el binding en la config permanente y recarga
// (los ipsets de firewalld solo pueden crearse en permanente).
func (f *ipsetFW) Setup(ctx context.Context) error {
	out, err := exec.CommandContext(ctx, "firewall-cmd", "--get-ipsets").Output()
	if err != nil {
		return fmt.Errorf("firewall-cmd --get-ipsets: %w", err)
	}
	hasSet := containsField(string(out), ipsetName)

	hasBinding := false
	if out, err := exec.CommandContext(ctx, "firewall-cmd", "--zone=drop", "--list-sources").Output(); err == nil {
		hasBinding = containsField(string(out), "ipset:"+ipsetName)
	}

	if hasSet && hasBinding {
		return nil
	}

	slog.Info("enforcement: inicializando ipset de firewalld", "ipset", ipsetName)
	// Crear set y binding en permanente. NAME_CONFLICT/ALREADY_ENABLED son
	// estados ya deseados: solo falta materializarlos con el reload.
	steps := [][]string{
		{"--permanent", "--new-ipset=" + ipsetName, "--type=hash:net"},
		{"--permanent", "--zone=drop", "--add-source=ipset:" + ipsetName},
	}
	for _, args := range steps {
		cmd := exec.CommandContext(ctx, "firewall-cmd", args...)
		if out, err := cmd.CombinedOutput(); err != nil {
			s := string(out)
			if strings.Contains(s, "NAME_CONFLICT") || strings.Contains(s, "ALREADY_ENABLED") {
				continue
			}
			return fmt.Errorf("firewall-cmd %v: %w — %s", args, err, strings.TrimSpace(s))
		}
	}
	if out, err := exec.CommandContext(ctx, "firewall-cmd", "--reload").CombinedOutput(); err != nil {
		return fmt.Errorf("firewall-cmd --reload: %w — %s", err, bytes.TrimSpace(out))
	}
	slog.Info("enforcement: ipset creado y enlazado a la zona drop", "ipset", ipsetName)
	return nil
}

// Block agrega la IP o CIDR al set. Las entradas temporales son solo runtime
// (runUnbanLoop las elimina al expirar); las permanentes (banSeconds=0) se
// escriben además en la config permanente para sobrevivir reloads y reboots.
func (f *ipsetFW) Block(ctx context.Context, ip string, banSeconds int) error {
	cmds := [][]string{{"--ipset=" + ipsetName, "--add-entry=" + ip}}
	if banSeconds == 0 {
		cmds = append(cmds, []string{"--permanent", "--ipset=" + ipsetName, "--add-entry=" + ip})
	}
	for _, args := range cmds {
		cmd := exec.CommandContext(ctx, "firewall-cmd", args...)
		if out, err := cmd.CombinedOutput(); err != nil {
			if strings.Contains(string(out), "ALREADY_ENABLED") {
				continue
			}
			return fmt.Errorf("firewall-cmd %v: %w — %s", args, err, bytes.TrimSpace(out))
		}
	}
	return nil
}

// Unblock elimina la entrada del set (runtime y permanente).
// Ignora errores de entradas inexistentes, igual que los otros backends.
func (f *ipsetFW) Unblock(ctx context.Context, ip string) error {
	exec.CommandContext(ctx, "firewall-cmd", "--ipset="+ipsetName, "--remove-entry="+ip).Run()
	exec.CommandContext(ctx, "firewall-cmd", "--permanent", "--ipset="+ipsetName, "--remove-entry="+ip).Run()
	return nil
}

// ListBlockedIPs retorna las entradas actuales del set (una por línea).
func (f *ipsetFW) ListBlockedIPs(ctx context.Context) ([]string, error) {
	out, err := exec.CommandContext(ctx, "firewall-cmd", "--ipset="+ipsetName, "--get-entries").Output()
	if err != nil {
		return nil, err
	}
	return parseIpsetEntries(out), nil
}

// parseIpsetEntries extrae las entradas válidas de `--get-entries`.
// Separado para tests sin el binario firewall-cmd.
func parseIpsetEntries(out []byte) []string {
	var entries []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && ValidBlockTarget(line) {
			entries = append(entries, line)
		}
	}
	return entries
}

// containsField retorna true si alguno de los campos (separados por espacios
// o saltos de línea) es exactamente s.
func containsField(out, s string) bool {
	for _, f := range strings.Fields(out) {
		if f == s {
			return true
		}
	}
	return false
}
