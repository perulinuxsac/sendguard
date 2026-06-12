//go:build linux

package enforcement

// Tests que requieren scripts shell y binarios de Linux (firewall-cmd, zmprov, etc.).
// Solo se compilan y ejecutan en Linux.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/perulinux/sendguard/internal/detection"
	"github.com/perulinux/sendguard/internal/store"
)

// setupFakeBin crea un script shell ejecutable que siempre termina con exit 0.
// Retorna el directorio que lo contiene (para anteponer a PATH o usar como sbinDir).
func setupFakeBin(t *testing.T, names ...string) string {
	t.Helper()
	dir := t.TempDir()
	for _, name := range names {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
			t.Fatalf("crear fake bin %q: %v", name, err)
		}
	}
	return dir
}

// prependPath añade dir al inicio de PATH y lo restaura al finalizar el test.
func prependPath(t *testing.T, dir string) {
	t.Helper()
	old := os.Getenv("PATH")
	t.Setenv("PATH", dir+":"+old)
}

// ── blockIP ──────────────────────────────────────────────────────────────────

func TestBlockIPTemporal(t *testing.T) {
	binDir := setupFakeBin(t, "firewall-cmd")
	prependPath(t, binDir)

	e := New(Config{BanSeconds: 3600})
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
		t.Fatalf("IP bloqueada: %v", blocked)
	}
}

func TestBlockIPPermanente(t *testing.T) {
	binDir := setupFakeBin(t, "firewall-cmd")
	prependPath(t, binDir)

	e := New(Config{BanSeconds: 0})
	e.blockIP(context.Background(), detection.Alert{
		IP: "2.2.2.2", Module: "test", Action: detection.ActionBlockIP, Timestamp: time.Now(),
	})

	if e.Stats().BlocksTotal != 1 {
		t.Errorf("permanente: BlocksTotal: got %d, want 1", e.Stats().BlocksTotal)
	}
}

func TestBlockIPDeduplicacion(t *testing.T) {
	binDir := setupFakeBin(t, "firewall-cmd")
	prependPath(t, binDir)

	e := New(Config{BanSeconds: 3600})
	alert := detection.Alert{IP: "3.3.3.3", Module: "test", Action: detection.ActionBlockIP, Timestamp: time.Now()}

	e.blockIP(context.Background(), alert)
	e.blockIP(context.Background(), alert) // dedup: no debe bloquear de nuevo

	if e.Stats().BlocksTotal != 1 {
		t.Errorf("dedup: BlocksTotal got %d, want 1", e.Stats().BlocksTotal)
	}
}

func TestBlockIPPersistidaEnStore(t *testing.T) {
	binDir := setupFakeBin(t, "firewall-cmd")
	prependPath(t, binDir)

	s, _ := store.Open(":memory:")
	defer s.Close()

	e := New(Config{BanSeconds: 3600, Store: s})
	e.blockIP(context.Background(), detection.Alert{
		IP: "4.4.4.4", Module: "test", Action: detection.ActionBlockIP, Timestamp: time.Now(),
	})

	bans, err := s.LoadActiveBans()
	if err != nil {
		t.Fatalf("LoadActiveBans: %v", err)
	}
	if len(bans) != 1 || bans[0].IP != "4.4.4.4" {
		t.Errorf("ban no persistido en store: %v", bans)
	}
}

// ── suspendAccount ───────────────────────────────────────────────────────────

func TestSuspendAccount(t *testing.T) {
	binDir := setupFakeBin(t, "zmprov")
	prependPath(t, binDir)

	// ZmprovBin explícito: suspendAccount usa por defecto la ruta absoluta
	// /opt/zimbra/bin/zmprov (correcto en producción, donde el PATH del servicio
	// no incluye /opt/zimbra/bin), por lo que el fake del PATH no se usaría.
	// Apuntar al fake hace el test determinista e independiente del entorno.
	e := New(Config{ZmprovBin: filepath.Join(binDir, "zmprov")})
	e.suspendAccount(context.Background(), detection.Alert{
		Account: "user@domain.com",
		Module:  "numbermessages",
	})

	if e.Stats().SuspensionsTotal != 1 {
		t.Errorf("SuspensionsTotal: got %d, want 1", e.Stats().SuspensionsTotal)
	}
}

// fakeUserNotifier captura los avisos enviados al usuario suspendido.
type fakeUserNotifier struct {
	accounts []string
	fail     bool
}

func (f *fakeUserNotifier) NotifySuspendedUser(_ context.Context, account string, _ detection.Alert) error {
	f.accounts = append(f.accounts, account)
	if f.fail {
		return fmt.Errorf("sendmail no disponible")
	}
	return nil
}

func TestSuspendAccountAvisaAlUsuario(t *testing.T) {
	binDir := setupFakeBin(t, "zmprov")
	prependPath(t, binDir)

	un := &fakeUserNotifier{}
	e := New(Config{ZmprovBin: filepath.Join(binDir, "zmprov"), UserNotifier: un})
	e.suspendAccount(context.Background(), detection.Alert{
		Account: "jalegre@sedachimbote.com.pe",
		Module:  "number_messages",
	})

	if len(un.accounts) != 1 || un.accounts[0] != "jalegre@sedachimbote.com.pe" {
		t.Errorf("aviso al usuario: got %v, want [jalegre@sedachimbote.com.pe]", un.accounts)
	}
}

func TestSuspendAccountFallidaNoAvisaAlUsuario(t *testing.T) {
	// zmprov que falla: la cuenta NO se suspendió, no debe enviarse el aviso.
	dir := t.TempDir()
	zmprov := filepath.Join(dir, "zmprov")
	os.WriteFile(zmprov, []byte("#!/bin/sh\nexit 1\n"), 0755)

	un := &fakeUserNotifier{}
	e := New(Config{ZmprovBin: zmprov, UserNotifier: un})
	e.suspendAccount(context.Background(), detection.Alert{
		Account: "user@domain.com", Module: "test",
	})

	if len(un.accounts) != 0 {
		t.Errorf("zmprov falló: no debe avisarse al usuario, got %v", un.accounts)
	}
}

func TestSuspendAccountAvisoFallidoNoRompeSuspension(t *testing.T) {
	binDir := setupFakeBin(t, "zmprov")
	prependPath(t, binDir)

	un := &fakeUserNotifier{fail: true}
	e := New(Config{ZmprovBin: filepath.Join(binDir, "zmprov"), UserNotifier: un})
	e.suspendAccount(context.Background(), detection.Alert{
		Account: "user@domain.com", Module: "test",
	})

	// El fallo del aviso solo se loguea: la suspensión queda registrada igual.
	if e.Stats().SuspensionsTotal != 1 {
		t.Errorf("SuspensionsTotal: got %d, want 1", e.Stats().SuspensionsTotal)
	}
}

// ── Block / Unblock (válidos) ────────────────────────────────────────────────

func TestBlock_Valid(t *testing.T) {
	binDir := setupFakeBin(t, "firewall-cmd")
	prependPath(t, binDir)

	e := New(Config{BanSeconds: 60})
	if err := e.Block(context.Background(), "5.5.5.5", 0); err != nil {
		t.Errorf("Block: %v", err)
	}
	blocked := e.BlockedIPs()
	if len(blocked) != 1 || blocked[0].IP != "5.5.5.5" {
		t.Errorf("Block: IP no en blockedIPs: %v", blocked)
	}
	if e.Stats().BlocksTotal != 1 {
		t.Errorf("Block: BlocksTotal got %d, want 1", e.Stats().BlocksTotal)
	}
}

func TestUnblock_Valid(t *testing.T) {
	binDir := setupFakeBin(t, "firewall-cmd")
	prependPath(t, binDir)

	e := New(Config{BanSeconds: 3600})

	e.mu.Lock()
	e.blockedIPs["6.6.6.6"] = blockedIP{expiry: time.Now().Add(time.Hour), module: "test"}
	e.mu.Unlock()

	if err := e.Unblock(context.Background(), "6.6.6.6"); err != nil {
		t.Errorf("Unblock: %v", err)
	}
	if len(e.BlockedIPs()) != 0 {
		t.Error("Unblock: IP debe eliminarse de blockedIPs")
	}
}

// ── Block / Unblock con CIDR ─────────────────────────────────────────────────

func TestBlockCIDR(t *testing.T) {
	binDir := setupFakeBin(t, "firewall-cmd")
	prependPath(t, binDir)

	e := New(Config{BanSeconds: 60})
	if err := e.Block(context.Background(), "200.25.47.0/24", -1); err != nil {
		t.Fatalf("Block CIDR: %v", err)
	}

	blocked := e.BlockedIPs()
	if len(blocked) != 1 || blocked[0].IP != "200.25.47.0/24" {
		t.Fatalf("Block CIDR: blockedIPs = %v, want [200.25.47.0/24]", blocked)
	}

	// El policy daemon consulta IPs individuales: deben matchear contra el rango.
	for _, ip := range []string{"200.25.47.116", "200.25.47.1", "200.25.47.254"} {
		if !e.IsBlocked(ip) {
			t.Errorf("IsBlocked(%s): got false, want true (dentro de 200.25.47.0/24)", ip)
		}
		info, ok := e.GetBlockedIP(ip)
		if !ok || info.IP != "200.25.47.0/24" {
			t.Errorf("GetBlockedIP(%s): got (%v, %v), want CIDR 200.25.47.0/24", ip, info, ok)
		}
	}
	if e.IsBlocked("200.25.48.1") {
		t.Error("IsBlocked(200.25.48.1): got true, want false (fuera del rango)")
	}
}

func TestBlockCIDRNormalizado(t *testing.T) {
	binDir := setupFakeBin(t, "firewall-cmd")
	prependPath(t, binDir)

	e := New(Config{BanSeconds: 60})
	// La dirección con bits de host ("...47.116/24") debe canonicalizarse a la red.
	if err := e.Block(context.Background(), "200.25.47.116/24", 0); err != nil {
		t.Fatalf("Block CIDR sin normalizar: %v", err)
	}
	blocked := e.BlockedIPs()
	if len(blocked) != 1 || blocked[0].IP != "200.25.47.0/24" {
		t.Fatalf("normalización: blockedIPs = %v, want [200.25.47.0/24]", blocked)
	}
}

func TestUnblockCIDR(t *testing.T) {
	binDir := setupFakeBin(t, "firewall-cmd")
	prependPath(t, binDir)

	e := New(Config{BanSeconds: 60})
	if err := e.Block(context.Background(), "203.0.113.0/24", -1); err != nil {
		t.Fatalf("Block: %v", err)
	}
	if err := e.Unblock(context.Background(), "203.0.113.0/24"); err != nil {
		t.Fatalf("Unblock CIDR: %v", err)
	}
	if len(e.BlockedIPs()) != 0 {
		t.Error("Unblock CIDR: el rango debe eliminarse de blockedIPs")
	}
	if e.IsBlocked("203.0.113.5") {
		t.Error("IsBlocked tras Unblock: got true, want false")
	}
}

func TestBlockCIDRPrivadoRetornaError(t *testing.T) {
	e := New(Config{BanSeconds: 60})
	for _, cidr := range []string{"192.168.0.0/16", "10.0.0.0/8", "127.0.0.0/8"} {
		if err := e.Block(context.Background(), cidr, 0); err == nil {
			t.Errorf("Block(%s): debe rechazar redes privadas/locales", cidr)
		}
	}
}

func TestBlockManualIgnoraPaisPermitido(t *testing.T) {
	// Regresión: en hosts con allowed_countries=[PE] el bloqueo manual de una
	// IP o rango peruano se omitía silenciosamente (skip por GeoIP) y el ctl
	// reportaba éxito sin haber bloqueado nada. El veto por país solo aplica
	// a las alertas automáticas; lo manual es decisión explícita del admin.
	binDir := setupFakeBin(t, "firewall-cmd")
	prependPath(t, binDir)

	srv := newGeoSrv(t, "PE")
	e := New(Config{BanSeconds: 60, GeoResolver: srv, AllowedCountries: []string{"PE"}})

	if err := e.Block(context.Background(), "200.25.47.0/24", -1); err != nil {
		t.Fatalf("Block manual: %v", err)
	}
	if !e.IsBlocked("200.25.47.116") {
		t.Error("bloqueo manual debe aplicarse aunque la IP sea de país permitido")
	}

	// Las alertas automáticas mantienen el skip por país permitido.
	e.blockIP(context.Background(), detection.Alert{
		IP: "190.40.1.1", Module: "authfailed",
		Action: detection.ActionBlockIP, Timestamp: time.Now(),
	})
	if e.IsBlocked("190.40.1.1") {
		t.Error("alerta automática de país permitido no debe bloquearse")
	}
}

func TestBlockSobreviveContextoCancelado(t *testing.T) {
	// Regresión: el contexto del request HTTP (timeout 10s del cliente) mataba
	// firewall-cmd a mitad de camino en hosts con firewalld lento. El bloqueo
	// manual debe completarse aunque el contexto del caller ya esté cancelado.
	binDir := setupFakeBin(t, "firewall-cmd")
	prependPath(t, binDir)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // el caller ya se rindió

	e := New(Config{BanSeconds: 60})
	if err := e.Block(ctx, "203.0.113.9", -1); err != nil {
		t.Fatalf("Block con ctx cancelado: %v", err)
	}
	if !e.IsBlocked("203.0.113.9") {
		t.Error("el bloqueo debe completarse aunque el contexto del request esté cancelado")
	}
}

func TestBlockCIDRPersistidoYRestaurado(t *testing.T) {
	binDir := setupFakeBin(t, "firewall-cmd")
	prependPath(t, binDir)

	s, _ := store.Open(":memory:")
	defer s.Close()

	e := New(Config{BanSeconds: 3600, Store: s})
	if err := e.Block(context.Background(), "198.51.100.0/24", -1); err != nil {
		t.Fatalf("Block: %v", err)
	}

	// Simular reinicio del agente: un Enforcer nuevo restaura desde SQLite
	// y debe reconstruir también el matching por rango.
	e2 := New(Config{BanSeconds: 3600, Store: s})
	e2.LoadExistingBans(context.Background())
	if !e2.IsBlocked("198.51.100.77") {
		t.Error("tras restaurar de SQLite: IP del rango debe seguir bloqueada")
	}
}

func TestUnblockEliminaDelStore(t *testing.T) {
	binDir := setupFakeBin(t, "firewall-cmd")
	prependPath(t, binDir)

	s, _ := store.Open(":memory:")
	defer s.Close()
	s.SaveBan("7.7.7.7", "test", time.Now().Add(time.Hour))

	e := New(Config{BanSeconds: 3600, Store: s})
	e.mu.Lock()
	e.blockedIPs["7.7.7.7"] = blockedIP{expiry: time.Now().Add(time.Hour), module: "test"}
	e.mu.Unlock()

	e.Unblock(context.Background(), "7.7.7.7")

	bans, _ := s.LoadActiveBans()
	if len(bans) != 0 {
		t.Errorf("Unblock: ban debe eliminarse del store: %v", bans)
	}
}

// ── loadBansFromFirewalld (con fake firewall-cmd que emite reglas) ────────────

func TestLoadBansFromFirewalld_ConReglas(t *testing.T) {
	// Fake firewall-cmd que imprime una rich-rule válida
	dir := t.TempDir()
	script := `#!/bin/sh
echo 'rule family="ipv4" source address="8.8.8.8" reject'
exit 0
`
	os.WriteFile(filepath.Join(dir, "firewall-cmd"), []byte(script), 0755)
	prependPath(t, dir)

	e := New(Config{BanSeconds: 3600})
	e.loadBansFromFirewalld(context.Background())

	blocked := e.BlockedIPs()
	if len(blocked) != 1 || blocked[0].IP != "8.8.8.8" {
		t.Errorf("loadBansFromFirewalld: esperado 1 IP (8.8.8.8), got %v", blocked)
	}
}

func TestLoadBansFromFirewalld_SinFirewalld(t *testing.T) {
	// Ruta vacía → firewall-cmd no encontrado → debe loguear y no fallar
	emptyDir := t.TempDir()
	t.Setenv("PATH", emptyDir)

	e := New(Config{BanSeconds: 3600})
	e.loadBansFromFirewalld(context.Background()) // no debe panic

	if len(e.BlockedIPs()) != 0 {
		t.Error("sin firewalld: no debe cargar IPs")
	}
}

// ── handle — ActionRateLimit con postmap real ────────────────────────────────

func TestHandleRateLimitConPostfix(t *testing.T) {
	sbinDir := setupFakeBin(t, "postmap")
	confDir := t.TempDir()

	e := New(Config{PostfixSbin: sbinDir, PostfixConf: confDir})
	e.handle(context.Background(), detection.Alert{
		Module:    "numbermessages",
		Action:    detection.ActionRateLimit,
		Account:   "spammer@domain.com",
		Timestamp: time.Now(),
	})

	if e.Stats().RateLimitsTotal != 1 {
		t.Errorf("RateLimitsTotal: got %d, want 1", e.Stats().RateLimitsTotal)
	}

	data, _ := os.ReadFile(filepath.Join(confDir, "sendguard_access"))
	if !strings.Contains(string(data), "spammer@domain.com") {
		t.Error("access file debe contener la cuenta")
	}
}

// ── handle — ActionPurgeQueue con postqueue/postsuper ───────────────────────

func TestHandlePurgeQueueColasVacias(t *testing.T) {
	sbinDir := t.TempDir()
	confDir := t.TempDir()

	os.WriteFile(filepath.Join(sbinDir, "postqueue"),
		[]byte("#!/bin/sh\necho 'Mail queue is empty'\nexit 0\n"), 0755)

	e := New(Config{PostfixSbin: sbinDir, PostfixConf: confDir})
	e.handle(context.Background(), detection.Alert{
		Module:    "test",
		Action:    detection.ActionPurgeQueue,
		Domain:    "target.com",
		Timestamp: time.Now(),
	})
	// No panic, no error — cola vacía es un caso normal
}
