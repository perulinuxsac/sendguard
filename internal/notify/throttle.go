package notify

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/perulinux/sendguard/internal/detection"
)

// ThrottleConfig configura los dos límites del ThrottledNotifier.
type ThrottleConfig struct {
	// KeyCooldown: tiempo mínimo entre notificaciones del mismo IP o cuenta.
	// Evita recibir múltiples alertas del mismo origen en poco tiempo.
	KeyCooldown time.Duration

	// MaxPerWindow: máximo de notificaciones totales en Window (0 = sin límite global).
	// Evita flood cuando cientos de IPs distintas atacan simultáneamente.
	MaxPerWindow int

	// Window: duración de la ventana del límite global (default: 1 minuto).
	Window time.Duration
}

// ThrottledNotifier envuelve un Notifier y aplica dos límites en cadena:
//  1. Cooldown por clave (IP o cuenta): suprime repeticiones del mismo origen.
//  2. Límite global por ventana: descarta exceso cuando muchas IPs atacan a la vez.
//
// Es thread-safe.
type ThrottledNotifier struct {
	inner Notifier
	cfg   ThrottleConfig

	mu          sync.Mutex
	keys        map[string]time.Time // clave → última notificación enviada
	windowStart time.Time
	windowCount int
	pruneCount  int
}

const (
	throttlePruneEvery = 500
	throttleMaxKeys    = 5_000 // poda forzada si el mapa supera este tamaño
)

// NewThrottled crea un ThrottledNotifier que envuelve inner.
// Si cfg.Window es 0, se usa 1 minuto por defecto.
func NewThrottled(inner Notifier, cfg ThrottleConfig) *ThrottledNotifier {
	if cfg.Window == 0 {
		cfg.Window = time.Minute
	}
	return &ThrottledNotifier{
		inner:       inner,
		cfg:         cfg,
		keys:        make(map[string]time.Time),
		windowStart: time.Now(),
	}
}

// throttleKey identifica el origen de la alerta para el cooldown. Incluye la
// acción y la cuenta además de la IP: con la IP a secas, la segunda cuenta
// suspendida desde la misma IP atacante dentro del cooldown se silenciaba —
// exactamente el patrón de un incidente masivo, cuando más se necesita ver todo.
func throttleKey(alert detection.Alert) string {
	if alert.IP == "" && alert.Account == "" {
		return string(alert.Action) + "|" + alert.Module
	}
	return string(alert.Action) + "|" + alert.IP + "|" + alert.Account
}

// Notify envía la notificación solo si pasa ambos filtros de throttling.
// El cooldown y la ventana se consumen DESPUÉS de un envío exitoso: un fallo
// transitorio del canal (sendmail, Telegram) no debe suprimir la alerta
// durante todo el cooldown.
func (t *ThrottledNotifier) Notify(ctx context.Context, alert detection.Alert) error {
	key := throttleKey(alert)
	now := time.Now()

	t.mu.Lock()

	// 1. Cooldown por clave: misma acción+IP+cuenta dentro del período de enfriamiento.
	if t.cfg.KeyCooldown > 0 {
		if last, ok := t.keys[key]; ok {
			remaining := t.cfg.KeyCooldown - now.Sub(last)
			if remaining > 0 {
				t.mu.Unlock()
				slog.Info("notify: cooldown activo, notificación suprimida",
					"key", key,
					"module", alert.Module,
					"remaining", remaining.Truncate(time.Second).String(),
				)
				return nil
			}
		}
	}

	// 2. Límite global por ventana: demasiadas notificaciones distintas en poco tiempo.
	if t.cfg.MaxPerWindow > 0 {
		if now.Sub(t.windowStart) >= t.cfg.Window {
			t.windowStart = now
			t.windowCount = 0
		}
		if t.windowCount >= t.cfg.MaxPerWindow {
			t.mu.Unlock()
			slog.Warn("notify: límite global alcanzado, notificación descartada",
				"max_per_window", t.cfg.MaxPerWindow,
				"window", t.cfg.Window,
				"module", alert.Module,
				"key", key,
			)
			return nil
		}
	}

	t.mu.Unlock()

	if err := t.inner.Notify(ctx, alert); err != nil {
		return err
	}

	// Envío exitoso: consumir cupo de ventana y registrar el cooldown.
	t.mu.Lock()
	if t.cfg.MaxPerWindow > 0 {
		t.windowCount++
	}
	if t.cfg.KeyCooldown > 0 {
		t.keys[key] = time.Now()
	}

	// Limpiar claves expiradas periódicamente o cuando el mapa sea demasiado grande.
	// La poda forzada por tamaño evita crecimiento ilimitado durante ataques masivos
	// con miles de IPs únicas antes de que se alcance el umbral de operaciones.
	t.pruneCount++
	if t.pruneCount >= throttlePruneEvery || len(t.keys) >= throttleMaxKeys {
		t.pruneCount = 0
		cutoff := time.Now().Add(-t.cfg.KeyCooldown)
		for k, ts := range t.keys {
			if ts.Before(cutoff) {
				delete(t.keys, k)
			}
		}
	}
	t.mu.Unlock()
	return nil
}
