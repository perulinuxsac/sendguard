package enforcement

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// safeTools son las únicas herramientas del sistema visibles para los tests
// (las usan los scripts falsos). firewall-cmd, ufw, ipset, postfix… quedan fuera.
var safeTools = []string{"sh", "cat", "echo", "printf", "true", "false", "grep", "sleep"}

// TestMain aísla todo el paquete del firewall real: PATH apunta a un
// directorio con enlaces solo a safeTools, así que un test que olvide su
// firewall falso falla al no encontrar firewall-cmd/ufw en lugar de crear
// reglas de verdad en el host (los tests corren como root en los servidores
// de desarrollo). Los tests que necesitan un binario falso lo anteponen con
// prependPath.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "sendguard-test-path")
	if err != nil {
		panic(err)
	}
	for _, tool := range safeTools {
		if p, err := exec.LookPath(tool); err == nil {
			_ = os.Symlink(p, filepath.Join(dir, tool))
		}
	}
	os.Setenv("PATH", dir)
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}
