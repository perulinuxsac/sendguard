package enforcement

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/perulinux/sendguard/internal/detection"
)

// memFW es un firewall en memoria: permite simular un reload que borra reglas.
type memFW struct {
	mu       sync.Mutex
	rules    map[string]int // ip → banSeconds del último Block
	blocks   []string
	unblocks []string
	listErr  error
	setupErr error
	setups   int
}

func newMemFW() *memFW { return &memFW{rules: map[string]int{}} }

func (f *memFW) Block(_ context.Context, ip string, banSeconds int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rules[ip] = banSeconds
	f.blocks = append(f.blocks, ip)
	return nil
}

func (f *memFW) Unblock(_ context.Context, ip string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.rules, ip)
	f.unblocks = append(f.unblocks, ip)
	return nil
}

func (f *memFW) ListBlockedIPs(context.Context) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listErr != nil {
		return nil, f.listErr
	}
	var out []string
	for ip := range f.rules {
		out = append(out, ip)
	}
	return out, nil
}

// memFWSetup añade Setup (como firewalld-ipset).
type memFWSetup struct{ *memFW }

func (f memFWSetup) Setup(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.setups++
	return f.setupErr
}

func blockAlert(ip, module string) detection.Alert {
	return detection.Alert{IP: ip, Module: module, Action: detection.ActionBlockIP, Timestamp: time.Now()}
}

// Un reload del firewall borra las reglas temporales; la conciliación debe
// reponerlas con el TTL restante y sin tocar las que siguen presentes.
func TestReconcileReponeBansPerdidos(t *testing.T) {
	for _, backend := range []string{"firewalld", "firewalld-ipset", "ufw"} {
		t.Run(backend, func(t *testing.T) {
			f := newMemFW()
			e := New(Config{BanSeconds: 3600, FirewallBackend: backend})
			e.fw = f
			ctx := context.Background()
			if err := e.blockIPWithTTL(ctx, blockAlert("1.2.3.4", "auth_failed"), 3600); err != nil {
				t.Fatal(err)
			}
			if err := e.blockIPWithTTL(ctx, blockAlert("5.6.7.8", "auth_failed"), 3600); err != nil {
				t.Fatal(err)
			}

			delete(f.rules, "1.2.3.4") // firewall-cmd --reload
			f.blocks = nil
			e.reconcileFirewall(ctx)

			if len(f.blocks) != 1 || f.blocks[0] != "1.2.3.4" {
				t.Fatalf("solo debe reponerse 1.2.3.4: got %v", f.blocks)
			}
			if ttl := f.rules["1.2.3.4"]; ttl <= 0 || ttl > 3601 {
				t.Errorf("debe reponerse con el TTL restante: got %d", ttl)
			}
		})
	}
}

// Si el firewall no se puede leer no se re-aplica nada a ciegas (en firewalld
// con --timeout duplicaría reglas); se reintenta en la próxima vuelta.
func TestReconcileSinListadoNoHaceNada(t *testing.T) {
	f := newMemFW()
	e := New(Config{BanSeconds: 3600})
	e.fw = f
	_ = e.blockIPWithTTL(context.Background(), blockAlert("1.2.3.4", "x"), 3600)
	f.blocks = nil
	f.listErr = errors.New("firewalld no responde")
	e.reconcileFirewall(context.Background())
	if len(f.blocks) != 0 {
		t.Errorf("no debe bloquear sin poder listar: got %v", f.blocks)
	}
}

// El agente arrancó antes que firewalld: Setup falla, y la conciliación lo
// reintenta hasta que funcione y luego repone los bans.
func TestReconcileReintentaSetup(t *testing.T) {
	f := memFWSetup{newMemFW()}
	f.setupErr = errors.New("FirewallD is not running")
	e := New(Config{BanSeconds: 3600, FirewallBackend: "firewalld-ipset"})
	e.fw = f
	e.blockedIPs["1.2.3.4"] = blockedIP{expiry: time.Now().Add(time.Hour), module: "restored"}

	e.LoadExistingBans(context.Background())
	if len(f.blocks) != 0 {
		t.Fatalf("sin Setup no debe bloquear: %v", f.blocks)
	}
	f.setupErr = nil
	e.reconcileFirewall(context.Background())
	if len(f.blocks) != 1 || f.blocks[0] != "1.2.3.4" {
		t.Fatalf("tras el Setup debe reponerse el ban: got %v", f.blocks)
	}
	setups := f.setups
	e.reconcileFirewall(context.Background())
	if f.setups != setups {
		t.Error("con Setup exitoso no debe repetirse")
	}
}

// "1.2.3.4" en el agente y "1.2.3.4/32" en el firewall son la misma entrada.
func TestReconcileNormalizaClaves(t *testing.T) {
	f := newMemFW()
	e := New(Config{BanSeconds: 3600, FirewallBackend: "firewalld-ipset"})
	e.fw = f
	e.blockedIPs["1.2.3.4"] = blockedIP{expiry: time.Now().Add(time.Hour)}
	f.rules["1.2.3.4/32"] = 0
	e.reconcileFirewall(context.Background())
	if len(f.blocks) != 0 {
		t.Errorf("no debe duplicar una entrada presente: got %v", f.blocks)
	}
}

// Bloqueo manual permanente sobre un ban temporal: debe quedar permanente.
func TestBlockManualPermanenteExtiendeBanTemporal(t *testing.T) {
	for _, backend := range []string{"firewalld", "firewalld-ipset"} {
		t.Run(backend, func(t *testing.T) {
			f := newMemFW()
			e := New(Config{BanSeconds: 3600, FirewallBackend: backend})
			e.fw = f
			ctx := context.Background()
			_ = e.blockIPWithTTL(ctx, blockAlert("5.6.7.8", "auth_failed"), 3600)

			if err := e.Block(ctx, "5.6.7.8", -1); err != nil {
				t.Fatal(err)
			}
			info, ok := e.GetBlockedIP("5.6.7.8")
			if !ok || time.Until(info.Expiry) < 50*365*24*time.Hour {
				t.Fatalf("debe quedar permanente: %+v", info)
			}
			if f.rules["5.6.7.8"] != 0 {
				t.Errorf("el firewall debe tener la regla permanente (ttl 0): got %d", f.rules["5.6.7.8"])
			}
			// En firewalld la regla temporal lleva su --timeout: hay que reemplazarla.
			if backend == "firewalld" && len(f.unblocks) != 1 {
				t.Errorf("firewalld: la regla temporal debe reemplazarse: unblocks=%v", f.unblocks)
			}
		})
	}
}

// Una alerta repetida con el mismo TTL sigue siendo un duplicado (no toca el firewall).
func TestBlockDuplicadoNoExtiende(t *testing.T) {
	f := newMemFW()
	e := New(Config{BanSeconds: 3600})
	e.fw = f
	ctx := context.Background()
	_ = e.blockIPWithTTL(ctx, blockAlert("5.6.7.8", "auth_failed"), 3600)
	_ = e.blockIPWithTTL(ctx, blockAlert("5.6.7.8", "auth_failed"), 3600)
	if len(f.blocks) != 1 || len(f.unblocks) != 0 {
		t.Errorf("duplicado: blocks=%v unblocks=%v", f.blocks, f.unblocks)
	}
}
