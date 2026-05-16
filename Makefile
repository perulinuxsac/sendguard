BINARY        := sendguard-agent
BINARY_CTL    := sendguard-ctl
BINARY_POLICYD := sendguard-policyd
BUILD_DIR   := dist
MODULE      := github.com/perulinux/sendguard
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT      := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE  := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
	-X $(MODULE)/internal/version.Version=$(VERSION) \
	-X $(MODULE)/internal/version.Commit=$(COMMIT) \
	-X $(MODULE)/internal/version.BuildDate=$(BUILD_DATE)

# Binario Linux amd64 estático (para deploy en servidores Zimbra)
GOFLAGS := CGO_ENABLED=0 GOOS=linux GOARCH=amd64

.PHONY: all build build-ctl build-policyd package test lint vet clean install install-ctl help

all: build build-ctl build-policyd

## build: compila el agente como binario estático Linux/amd64 en dist/
build:
	@mkdir -p $(BUILD_DIR)
	$(GOFLAGS) go build -trimpath -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY) ./cmd/agent
	@echo "Binario generado: $(BUILD_DIR)/$(BINARY)"

## build-ctl: compila sendguard-ctl en dist/
build-ctl:
	@mkdir -p $(BUILD_DIR)
	$(GOFLAGS) go build -trimpath -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_CTL) ./cmd/ctl
	@echo "Binario generado: $(BUILD_DIR)/$(BINARY_CTL)"

## build-policyd: compila sendguard-policyd (daemon de políticas Postfix) en dist/
build-policyd:
	@mkdir -p $(BUILD_DIR)
	$(GOFLAGS) go build -trimpath -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_POLICYD) ./cmd/policyd
	@echo "Binario generado: $(BUILD_DIR)/$(BINARY_POLICYD)"

## test: ejecuta todos los tests con cobertura
test:
	go test -race -count=1 -coverprofile=coverage.out ./...
	@go tool cover -func=coverage.out | tail -1

## test-v: tests con salida detallada
test-v:
	go test -race -count=1 -v ./...

## vet: análisis estático con go vet
vet:
	go vet ./...

## lint: análisis estático con golangci-lint (debe estar instalado)
lint:
	golangci-lint run ./...

## package: compila y empaqueta todo para deploy en un tar.gz
package: build build-ctl build-policyd
	@mkdir -p $(BUILD_DIR)
	tar -czf $(BUILD_DIR)/sendguard-$(VERSION).tar.gz \
		-C $(BUILD_DIR) $(BINARY) $(BINARY_CTL) $(BINARY_POLICYD) \
		-C $(CURDIR)/deploy sendguard-agent.service sendguard-policyd.service install.sh test_sendguard.sh
	@echo "Paquete generado: $(BUILD_DIR)/sendguard-$(VERSION).tar.gz"
	@echo "Copiar al cliente:  scp $(BUILD_DIR)/sendguard-$(VERSION).tar.gz root@IP:/tmp/"
	@echo "Instalar:           tar xzf sendguard-$(VERSION).tar.gz && bash install.sh"

## clean: elimina binarios y artefactos generados
clean:
	rm -rf $(BUILD_DIR) coverage.out

## install: instala el binario en /usr/local/bin (requiere sudo)
install: build
	install -m 755 $(BUILD_DIR)/$(BINARY) /usr/local/bin/$(BINARY)
	@echo "Instalado en /usr/local/bin/$(BINARY)"

## install-ctl: instala sendguard-ctl en /usr/local/bin (requiere sudo)
install-ctl: build-ctl
	install -m 755 $(BUILD_DIR)/$(BINARY_CTL) /usr/local/bin/$(BINARY_CTL)
	@echo "Instalado en /usr/local/bin/$(BINARY_CTL)"

## install-service: instala binario + servicio systemd
install-service: install
	install -m 640 -D agent.yaml /etc/sendguard/agent.yaml
	install -m 644 deploy/sendguard-agent.service /etc/systemd/system/
	systemctl daemon-reload
	@echo "Servicio instalado. Edita /etc/sendguard/agent.yaml y ejecuta:"
	@echo "  systemctl enable --now sendguard-agent"

## help: muestra este mensaje de ayuda
help:
	@grep -E '^## ' Makefile | sed 's/## /  make /'
