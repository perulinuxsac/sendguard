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

// fakeZmprov crea un zmprov falso con el código de salida y la salida dados.
func fakeZmprov(t *testing.T, exitCode int, output string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "zmprov")
	script := "#!/bin/sh\necho '" + output + "'\nexit " + string(rune('0'+exitCode)) + "\n"
	if err := os.WriteFile(path, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	return path
}

func suspendAlert(ip string) detection.Alert {
	return detection.Alert{Module: "account_takeover", Action: detection.ActionSuspendAcct,
		Account: "user@dominio.pe", IP: ip, Score: 95, Timestamp: time.Now()}
}

// (a) Si zmprov falla, la alerta sale como fallida con el error, sin bloquear
// la IP ni contar la suspensión. Antes llegaba como "Cuenta suspendida".
func TestSuspensionFallidaSeNotificaComoFallo(t *testing.T) {
	n := &captureNotifier{}
	f := newMemFW()
	e := New(Config{Notifier: n, ZmprovBin: fakeZmprov(t, 1, "ERROR: account.NO_SUCH_ACCOUNT"), BanSeconds: 3600})
	e.fw = f

	e.handle(context.Background(), suspendAlert("203.0.113.7"))

	if len(n.alerts) != 1 {
		t.Fatalf("un fallo debe notificarse: got %d", len(n.alerts))
	}
	a := n.alerts[0]
	if a.Outcome != detection.OutcomeFailed || !strings.Contains(a.OutcomeDetail, "NO_SUCH_ACCOUNT") {
		t.Errorf("outcome=%q detail=%q, want failed con el error de zmprov", a.Outcome, a.OutcomeDetail)
	}
	if len(f.blocks) != 0 || e.Stats().SuspensionsTotal != 0 {
		t.Errorf("sin suspensión no se bloquea la IP ni se cuenta: blocks=%v susp=%d", f.blocks, e.Stats().SuspensionsTotal)
	}
}

// Suspensión aplicada: efectos en orden (cuenta, IP) y outcome applied.
func TestSuspensionAplicadaListaEfectos(t *testing.T) {
	n := &captureNotifier{}
	e := New(Config{Notifier: n, ZmprovBin: fakeZmprov(t, 0, ""), BanSeconds: 3600})
	e.fw = newMemFW()

	e.handle(context.Background(), suspendAlert("203.0.113.7"))

	a := n.alerts[0]
	if a.Outcome != detection.OutcomeApplied || a.OutcomeDetail != "" {
		t.Errorf("outcome=%q detail=%q, want applied sin detalle", a.Outcome, a.OutcomeDetail)
	}
	if len(a.Effects) != 2 || !strings.Contains(a.Effects[0].Text, "Cuenta bloqueada") ||
		!strings.Contains(a.Effects[1].Text, "203.0.113.7 bloqueada en el firewall por 1 h") {
		t.Errorf("efectos: %+v", a.Effects)
	}
}

// Una segunda alerta sobre una cuenta ya suspendida sale como "already".
func TestCuentaYaSuspendidaEsAlready(t *testing.T) {
	n := &captureNotifier{}
	e := New(Config{Notifier: n, ZmprovBin: fakeZmprov(t, 0, ""), BanSeconds: 3600})
	e.fw = newMemFW()

	e.handle(context.Background(), suspendAlert("203.0.113.7"))
	e.handle(context.Background(), suspendAlert("198.51.100.9"))

	if len(n.alerts) != 2 {
		t.Fatalf("got %d alerts", len(n.alerts))
	}
	a := n.alerts[1]
	if a.Outcome != detection.OutcomeAlready || !strings.Contains(a.OutcomeDetail, "ya estaba suspendida") {
		t.Errorf("outcome=%q detail=%q, want already", a.Outcome, a.OutcomeDetail)
	}
	// La IP nueva sí se bloquea.
	if len(a.Effects) != 2 || a.Effects[1].Outcome != detection.OutcomeApplied {
		t.Errorf("la IP nueva debe bloquearse: %+v", a.Effects)
	}
}

// (c) only_applied: no se notifica lo omitido ni lo ya aplicado; los fallos sí.
func TestOnlyAppliedFiltraOmitidasYYaAplicadas(t *testing.T) {
	n := &captureNotifier{}
	e := New(Config{
		Notifier:          n,
		ZmprovBin:         fakeZmprov(t, 0, ""),
		BanSeconds:        3600,
		GeoResolver:       newGeoSrv(t, "PE"),
		AllowedCountries:  []string{"PE"},
		NotifyOnActions:   []string{"suspend_account"},
		NotifyOnlyApplied: true,
	})
	e.fw = newMemFW()
	ctx := context.Background()

	e.handle(ctx, suspendAlert("161.132.1.1")) // PE → omitida: no se notifica
	if len(n.alerts) != 0 {
		t.Fatalf("omitida por país permitido no debe notificarse: %+v", n.alerts)
	}

	e.cfg.GeoResolver = nil // sin geo: la suspensión se aplica
	e.handle(ctx, suspendAlert("203.0.113.7"))
	e.handle(ctx, suspendAlert("203.0.113.8")) // ya suspendida: no se notifica
	if len(n.alerts) != 1 || n.alerts[0].Outcome != detection.OutcomeApplied {
		t.Fatalf("solo la aplicada debe notificarse: %+v", n.alerts)
	}

	e.cfg.ZmprovBin = fakeZmprov(t, 1, "zmprov caído")
	a := suspendAlert("203.0.113.9")
	a.Account = "otra@dominio.pe"
	e.handle(ctx, a) // fallo: se notifica siempre
	if len(n.alerts) != 2 || n.alerts[1].Outcome != detection.OutcomeFailed {
		t.Fatalf("un fallo debe notificarse aun con only_applied: %+v", n.alerts)
	}
}
