package notify_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/perulinux/sendguard/internal/detection"
	"github.com/perulinux/sendguard/internal/notify"
)

type countNotifier struct{ calls atomic.Int64 }

func (c *countNotifier) Notify(_ context.Context, _ detection.Alert) error {
	c.calls.Add(1)
	return nil
}

func alert(ip, account, module string) detection.Alert {
	return detection.Alert{IP: ip, Account: account, Module: module, Timestamp: time.Now()}
}

func TestThrottle_KeyCooldown(t *testing.T) {
	inner := &countNotifier{}
	th := notify.NewThrottled(inner, notify.ThrottleConfig{
		KeyCooldown: 10 * time.Second,
	})
	ctx := context.Background()

	th.Notify(ctx, alert("1.2.3.4", "", "auth_failed"))    // pasa
	th.Notify(ctx, alert("1.2.3.4", "", "auth_failed"))    // suprimida (cooldown)
	th.Notify(ctx, alert("1.2.3.4", "", "password_spray")) // suprimida (misma IP)
	th.Notify(ctx, alert("5.5.5.5", "", "auth_failed"))    // pasa (IP distinta)

	if got := inner.calls.Load(); got != 2 {
		t.Errorf("esperadas 2 notificaciones enviadas, got %d", got)
	}
}

func TestThrottle_MaxPerWindow(t *testing.T) {
	inner := &countNotifier{}
	th := notify.NewThrottled(inner, notify.ThrottleConfig{
		MaxPerWindow: 3,
		Window:       time.Minute,
	})
	ctx := context.Background()

	for i := 0; i < 10; i++ {
		ip := "1.2.3." + string(rune('0'+i))
		th.Notify(ctx, alert(ip, "", "auth_failed"))
	}

	if got := inner.calls.Load(); got != 3 {
		t.Errorf("esperadas 3 notificaciones (límite global), got %d", got)
	}
}

func TestThrottle_CooldownExpirado(t *testing.T) {
	inner := &countNotifier{}
	th := notify.NewThrottled(inner, notify.ThrottleConfig{
		KeyCooldown: 10 * time.Millisecond,
	})
	ctx := context.Background()

	th.Notify(ctx, alert("1.2.3.4", "", "auth_failed"))
	time.Sleep(20 * time.Millisecond)
	th.Notify(ctx, alert("1.2.3.4", "", "auth_failed")) // cooldown expirado, debe pasar

	if got := inner.calls.Load(); got != 2 {
		t.Errorf("esperadas 2 notificaciones tras expiración de cooldown, got %d", got)
	}
}

func TestThrottle_SinLimites(t *testing.T) {
	inner := &countNotifier{}
	th := notify.NewThrottled(inner, notify.ThrottleConfig{}) // sin cooldown ni límite global
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		th.Notify(ctx, alert("1.2.3.4", "", "auth_failed"))
	}

	if got := inner.calls.Load(); got != 5 {
		t.Errorf("sin límites todas deben pasar, got %d", got)
	}
}

func TestThrottle_ClaveEsCuenta(t *testing.T) {
	inner := &countNotifier{}
	th := notify.NewThrottled(inner, notify.ThrottleConfig{
		KeyCooldown: 10 * time.Second,
	})
	ctx := context.Background()

	th.Notify(ctx, alert("", "user@x.com", "bounce_rate"))  // pasa
	th.Notify(ctx, alert("", "user@x.com", "bounce_rate"))  // suprimida (misma cuenta)
	th.Notify(ctx, alert("", "other@x.com", "bounce_rate")) // pasa (cuenta distinta)

	if got := inner.calls.Load(); got != 2 {
		t.Errorf("esperadas 2, got %d", got)
	}
}

func TestThrottle_VentanaGlobalReset(t *testing.T) {
	inner := &countNotifier{}
	th := notify.NewThrottled(inner, notify.ThrottleConfig{
		MaxPerWindow: 2,
		Window:       20 * time.Millisecond,
	})
	ctx := context.Background()

	th.Notify(ctx, alert("1.1.1.1", "", "m")) // pasa
	th.Notify(ctx, alert("2.2.2.2", "", "m")) // pasa
	th.Notify(ctx, alert("3.3.3.3", "", "m")) // descartada (límite)

	time.Sleep(30 * time.Millisecond) // ventana expira

	th.Notify(ctx, alert("4.4.4.4", "", "m")) // pasa (nueva ventana)

	if got := inner.calls.Load(); got != 3 {
		t.Errorf("esperadas 3 (2 + 1 tras reset), got %d", got)
	}
}

// ── Correcciones de la auditoría jul-2026 ─────────────────────────────────────

type flakyNotifier struct {
	calls atomic.Int64
	fail  atomic.Bool
}

func (f *flakyNotifier) Notify(_ context.Context, _ detection.Alert) error {
	f.calls.Add(1)
	if f.fail.Load() {
		return errors.New("canal caído")
	}
	return nil
}

func TestThrottle_FalloDeEnvioNoConsumeCooldown(t *testing.T) {
	// Un fallo transitorio del canal no debe suprimir la alerta durante todo el
	// cooldown: el reintento inmediato tiene que poder pasar.
	inner := &flakyNotifier{}
	inner.fail.Store(true)
	th := notify.NewThrottled(inner, notify.ThrottleConfig{KeyCooldown: time.Minute})
	ctx := context.Background()

	a := alert("1.2.3.4", "user@d.com", "auth_failed")
	if err := th.Notify(ctx, a); err == nil {
		t.Fatal("el error del canal debe propagarse")
	}

	inner.fail.Store(false)
	if err := th.Notify(ctx, a); err != nil {
		t.Fatalf("el reintento tras el fallo debe pasar: %v", err)
	}
	if got := inner.calls.Load(); got != 2 {
		t.Errorf("llamadas al canal: got %d, want 2", got)
	}

	// Ahora sí: el envío exitoso activó el cooldown.
	th.Notify(ctx, a)
	if got := inner.calls.Load(); got != 2 {
		t.Errorf("tras el éxito el cooldown debe aplicar: got %d llamadas, want 2", got)
	}
}

func TestThrottle_CuentasDistintasMismaIPNoSeSilencian(t *testing.T) {
	// Incidente masivo: varias cuentas suspendidas desde la misma IP atacante.
	// Cada cuenta debe notificarse; solo las repeticiones exactas se suprimen.
	inner := &countNotifier{}
	th := notify.NewThrottled(inner, notify.ThrottleConfig{KeyCooldown: time.Minute})
	ctx := context.Background()

	a1 := detection.Alert{IP: "1.2.3.4", Account: "a@d.com", Module: "number_messages",
		Action: detection.ActionSuspendAcct, Timestamp: time.Now()}
	a2 := detection.Alert{IP: "1.2.3.4", Account: "b@d.com", Module: "number_messages",
		Action: detection.ActionSuspendAcct, Timestamp: time.Now()}

	th.Notify(ctx, a1) // pasa
	th.Notify(ctx, a2) // pasa (cuenta distinta, misma IP)
	th.Notify(ctx, a1) // suprimida (repetición exacta)

	if got := inner.calls.Load(); got != 2 {
		t.Errorf("esperadas 2 notificaciones (una por cuenta), got %d", got)
	}
}
