package detection

import "github.com/perulinux/sendguard/internal/event"

// Module es la interfaz que implementa cada módulo de detección.
// Handle recibe un evento y retorna 0 o más alertas.
// Handle se llama siempre desde el goroutine del Engine → no necesita ser thread-safe
// a menos que el módulo tenga goroutines de fondo propias.
type Module interface {
	Name() string
	Handle(ev event.Event) []Alert
}
