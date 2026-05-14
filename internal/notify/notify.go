// Package notify define la interfaz de notificaciones y provee implementaciones
// compuestas. Cada canal de notificación (Telegram, email, etc.) implementa Notifier.
package notify

import (
	"context"

	"github.com/perulinux/sendguard/internal/detection"
)

// Notifier envía una notificación cuando el Enforcer ejecuta una acción.
type Notifier interface {
	Notify(ctx context.Context, alert detection.Alert) error
}

// Noop es un Notifier que no hace nada. Se usa como valor por defecto cuando
// no hay canales de notificación configurados, evitando comprobaciones de nil.
type Noop struct{}

func (Noop) Notify(_ context.Context, _ detection.Alert) error { return nil }

// Multi envía la alerta a todos los Notifiers registrados.
// Si varios fallan, retorna el primer error pero continúa con los demás.
type Multi struct {
	notifiers []Notifier
}

// NewMulti crea un Multi con los notifiers indicados. Si se pasa uno solo,
// retorna ese notifier directamente para evitar una indirección innecesaria.
func NewMulti(nn ...Notifier) Notifier {
	active := make([]Notifier, 0, len(nn))
	for _, n := range nn {
		if n != nil {
			active = append(active, n)
		}
	}
	switch len(active) {
	case 0:
		return Noop{}
	case 1:
		return active[0]
	default:
		return &Multi{notifiers: active}
	}
}

func (m *Multi) Notify(ctx context.Context, alert detection.Alert) error {
	var first error
	for _, n := range m.notifiers {
		if err := n.Notify(ctx, alert); err != nil && first == nil {
			first = err
		}
	}
	return first
}
