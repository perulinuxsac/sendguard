// sendguard-policyd es el daemon de políticas Postfix de SendGuard.
// Se integra con Postfix via check_policy_service y rechaza conexiones SMTP
// de IPs bloqueadas por el agente en tiempo real — antes de que el cliente
// llegue a enviar el comando MAIL FROM.
//
// Configuración en Postfix (una sola vez via zmprov):
//
//	zmprov mcf zimbraMtaSmtpdRecipientRestrictions \
//	  "check_policy_service inet:127.0.0.1:9100" \
//	  "permit_mynetworks" \
//	  "permit_sasl_authenticated" \
//	  "reject_unauth_destination"
//
// El daemon consulta al agente vía GET /blocked/{ip} y cachea la respuesta
// 10 segundos para no saturar la API durante ataques de alta frecuencia.
// Si el agente no responde, retorna DUNNO (fail-open) para no interrumpir el servicio.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/perulinux/sendguard/internal/config"
)

const (
	defaultListen   = "127.0.0.1:9100"
	cacheTTL        = 10 * time.Second
	agentTimeout    = 500 * time.Millisecond // el agente es local — 500 ms es generoso
)

// cacheEntry almacena el resultado de una consulta al agente con su expiración.
type cacheEntry struct {
	blocked   bool
	expiresAt time.Time
}

// checker consulta el agente y mantiene la caché de resultados.
type checker struct {
	agentURL   string
	httpClient *http.Client
	mu         sync.Mutex
	cache      map[string]cacheEntry
}

func newChecker(agentBase string) *checker {
	return &checker{
		agentURL:   strings.TrimRight(agentBase, "/"),
		httpClient: &http.Client{Timeout: agentTimeout},
		cache:      make(map[string]cacheEntry),
	}
}

// isBlocked retorna true si la IP está bloqueada según el agente.
// Usa caché de 10 s para reducir carga durante ataques masivos.
func (c *checker) isBlocked(ip string) bool {
	now := time.Now()

	c.mu.Lock()
	if entry, ok := c.cache[ip]; ok && now.Before(entry.expiresAt) {
		blocked := entry.blocked
		c.mu.Unlock()
		return blocked
	}
	c.mu.Unlock()

	blocked := c.queryAgent(ip)

	c.mu.Lock()
	c.cache[ip] = cacheEntry{blocked: blocked, expiresAt: now.Add(cacheTTL)}
	// Limpiar entradas expiradas si el mapa crece demasiado.
	if len(c.cache) > 10_000 {
		for k, v := range c.cache {
			if now.After(v.expiresAt) {
				delete(c.cache, k)
			}
		}
	}
	c.mu.Unlock()

	return blocked
}

// queryAgent consulta GET /blocked/{ip} en la API del agente.
// Ante cualquier error retorna false (fail-open).
func (c *checker) queryAgent(ip string) bool {
	url := fmt.Sprintf("%s/blocked/%s", c.agentURL, ip)
	resp, err := c.httpClient.Get(url)
	if err != nil {
		slog.Warn("policyd: no se pudo consultar al agente", "ip", ip, "error", err)
		return false
	}
	defer resp.Body.Close()

	var body struct {
		Blocked bool `json:"blocked"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		slog.Warn("policyd: respuesta inválida del agente", "ip", ip, "error", err)
		return false
	}
	return body.Blocked
}

// handleConn atiende una conexión del smtpd de Postfix.
// El protocolo es: pares clave=valor terminados por línea vacía → responde action=...\n\n
func handleConn(conn net.Conn, chk *checker) {
	defer conn.Close()
	scanner := bufio.NewScanner(conn)
	attrs := make(map[string]string, 16)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			// Fin de la solicitud — evaluar y responder.
			action := evaluate(attrs, chk)
			fmt.Fprintf(conn, "action=%s\n\n", action)
			// Limpiar para la próxima solicitud en la misma conexión (persistent).
			attrs = make(map[string]string, 16)
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			attrs[k] = v
		}
	}
}

// evaluate decide la acción para una solicitud de política.
func evaluate(attrs map[string]string, chk *checker) string {
	ip := attrs["client_address"]
	if ip == "" || net.ParseIP(ip) == nil {
		return "DUNNO"
	}
	if chk.isBlocked(ip) {
		slog.Info("policyd: conexión rechazada", "ip", ip,
			"sender", attrs["sender"], "recipient", attrs["recipient"])
		return "REJECT Blocked by SendGuard — contact your administrator"
	}
	return "DUNNO"
}

func main() {
	configPath := flag.String("config", "/etc/sendguard/agent.yaml", "ruta al archivo de configuración")
	listen := flag.String("listen", "", "dirección de escucha (override de policy_daemon.listen en config)")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.Error("policyd: no se pudo cargar la configuración", "error", err)
		os.Exit(1)
	}

	addr := cfg.PolicyDaemon.Listen
	if *listen != "" {
		addr = *listen
	}
	if addr == "" {
		addr = defaultListen
	}

	agentBase := "http://127.0.0.1:9099"
	if cfg.API.Listen != "" {
		agentBase = "http://" + cfg.API.Listen
	}

	chk := newChecker(agentBase)

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		slog.Error("policyd: no se pudo abrir el socket", "addr", addr, "error", err)
		os.Exit(1)
	}
	slog.Info("sendguard-policyd iniciado",
		"listen", addr,
		"agent_api", agentBase,
		"cache_ttl", cacheTTL,
	)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		slog.Info("policyd: señal recibida, cerrando", "signal", sig)
		ln.Close()
		os.Exit(0)
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			slog.Warn("policyd: error al aceptar conexión", "error", err)
			continue
		}
		go handleConn(conn, chk)
	}
}
