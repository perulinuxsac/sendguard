// Package version expone la información de build inyectada por el linker
// durante `make build`. En desarrollo retorna valores de marcador.
package version

var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)
