// Package api expone un servidor HTTP para observabilidad y control del agente.
//
// Endpoints públicos (sin clave):
//
//	GET    /health              — liveness check
//	GET    /status              — estado: IPs bloqueadas, contadores
//	GET    /metrics             — métricas Prometheus text
//	GET    /urban/{ip}          — inteligencia de IP (AbuseIPDB + GeoIP)
//	GET    /queue               — cola de correo Postfix actual
//	GET    /domains             — dominios con alertas acumuladas
//	GET    /whitelist           — contenido actual de la whitelist
//
// Endpoints protegidos (requieren X-Api-Key si está configurada):
//
//	POST   /blocked/{ip}        — bloquear IP manualmente
//	DELETE /blocked/{ip}        — desbloquear IP manualmente
//	POST   /whitelist/{value}   — agregar IP/CIDR o cuenta a la whitelist
//	DELETE /whitelist/{value}   — eliminar IP/CIDR o cuenta de la whitelist
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/perulinux/sendguard/internal/abuseipdb"
	"github.com/perulinux/sendguard/internal/detection"
	"github.com/perulinux/sendguard/internal/enforcement"
	"github.com/perulinux/sendguard/internal/version"
)

// Dependencies agrupa las dependencias que el servidor necesita.
// Los campos opcionales (AbuseIPDB, GeoIP, Whitelist, PostfixSbin/Conf)
// pueden ser nil/vacío — los endpoints correspondientes responden con 503.
type Dependencies struct {
	Enforcer interface {
		BlockedIPs() []enforcement.BlockedIPInfo
		Stats() enforcement.EnforcerStats
		Unblock(ctx context.Context, ip string) error
		Block(ctx context.Context, ip string) error
	}
	Engine interface {
		EventsTotal() int64
		AlertsTotal() int64
		DomainStats() []detection.DomainStat
	}
	Whitelist interface {
		List() (ips []string, accounts []string)
		AddIP(ip string) error
		RemoveIP(ip string)
		AddAccount(account string)
		RemoveAccount(account string)
	}
	AbuseIPDB interface {
		Check(ctx context.Context, ip string) (abuseipdb.Report, error)
	}
	GeoIP interface {
		Country(ip string) string
	}
	PostfixSbin string
	PostfixConf string
	StartTime   time.Time
	APIKey      string // si no está vacío, los endpoints de escritura exigen X-Api-Key
}

// Server es el servidor HTTP del agente.
type Server struct {
	deps Dependencies
	srv  *http.Server
}

// New crea un Server que escucha en addr.
func New(addr string, deps Dependencies) *Server {
	if deps.StartTime.IsZero() {
		deps.StartTime = time.Now()
	}

	mux := http.NewServeMux()
	s := &Server{deps: deps}

	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("GET /status", s.handleStatus)
	mux.HandleFunc("GET /metrics", s.handleMetrics)
	mux.HandleFunc("GET /urban/{ip}", s.handleUrban)
	mux.HandleFunc("GET /queue", s.handleQueue)
	mux.HandleFunc("GET /domains", s.handleDomains)
	mux.HandleFunc("GET /whitelist", s.handleWhitelistGet)
	mux.HandleFunc("DELETE /blocked/{ip}", s.requireKey(s.handleUnblock))
	mux.HandleFunc("POST /blocked/{ip}", s.requireKey(s.handleBlock))
	mux.HandleFunc("POST /whitelist/{value}", s.requireKey(s.handleWhitelistAdd))
	mux.HandleFunc("DELETE /whitelist/{value}", s.requireKey(s.handleWhitelistRemove))

	s.srv = &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	return s
}

// ServeHTTP implementa http.Handler para facilitar el testing sin levantar un puerto.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.srv.Handler.ServeHTTP(w, r)
}

// Run inicia el servidor y bloquea hasta que ctx sea cancelado.
func (s *Server) Run(ctx context.Context) {
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.srv.Shutdown(shutCtx)
	}()

	slog.Info("api: servidor HTTP iniciado", "addr", s.srv.Addr)
	if err := s.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		slog.Error("api: servidor HTTP falló", "error", err)
	}
}

// --- handlers existentes ---

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"version": version.Version,
	})
}

type statusResponse struct {
	Uptime     string          `json:"uptime"`
	Version    string          `json:"version"`
	BlockedIPs []blockedIPJSON `json:"blocked_ips"`
	Stats      statsJSON       `json:"stats"`
}

type blockedIPJSON struct {
	IP        string    `json:"ip"`
	ExpiresAt time.Time `json:"expires_at"`
	Module    string    `json:"module"`
	TTL       string    `json:"ttl"`
}

type statsJSON struct {
	EventsTotal      int64 `json:"events_total"`
	AlertsTotal      int64 `json:"alerts_total"`
	BlocksTotal      int64 `json:"blocks_total"`
	SuspensionsTotal int64 `json:"suspensions_total"`
	RateLimitsTotal  int64 `json:"rate_limits_total"`
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	blocked := s.deps.Enforcer.BlockedIPs()
	ips := make([]blockedIPJSON, 0, len(blocked))
	now := time.Now()
	for _, b := range blocked {
		ttl := b.Expiry.Sub(now)
		if ttl < 0 {
			ttl = 0
		}
		ips = append(ips, blockedIPJSON{
			IP:        b.IP,
			ExpiresAt: b.Expiry,
			Module:    b.Module,
			TTL:       ttl.Truncate(time.Second).String(),
		})
	}

	enfStats := s.deps.Enforcer.Stats()
	resp := statusResponse{
		Uptime:     time.Since(s.deps.StartTime).Truncate(time.Second).String(),
		Version:    version.Version,
		BlockedIPs: ips,
		Stats: statsJSON{
			EventsTotal:      s.deps.Engine.EventsTotal(),
			AlertsTotal:      s.deps.Engine.AlertsTotal(),
			BlocksTotal:      enfStats.BlocksTotal,
			SuspensionsTotal: enfStats.SuspensionsTotal,
			RateLimitsTotal:  enfStats.RateLimitsTotal,
		},
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	enfStats := s.deps.Enforcer.Stats()
	blocked := s.deps.Enforcer.BlockedIPs()

	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintf(w, "# HELP sendguard_events_total Eventos procesados por el engine\n")
	fmt.Fprintf(w, "# TYPE sendguard_events_total counter\n")
	fmt.Fprintf(w, "sendguard_events_total %d\n\n", s.deps.Engine.EventsTotal())

	fmt.Fprintf(w, "# HELP sendguard_alerts_total Alertas emitidas por los módulos\n")
	fmt.Fprintf(w, "# TYPE sendguard_alerts_total counter\n")
	fmt.Fprintf(w, "sendguard_alerts_total %d\n\n", s.deps.Engine.AlertsTotal())

	fmt.Fprintf(w, "# HELP sendguard_blocks_total IPs bloqueadas por firewall\n")
	fmt.Fprintf(w, "# TYPE sendguard_blocks_total counter\n")
	fmt.Fprintf(w, "sendguard_blocks_total %d\n\n", enfStats.BlocksTotal)

	fmt.Fprintf(w, "# HELP sendguard_suspensions_total Cuentas suspendidas vía zmprov\n")
	fmt.Fprintf(w, "# TYPE sendguard_suspensions_total counter\n")
	fmt.Fprintf(w, "sendguard_suspensions_total %d\n\n", enfStats.SuspensionsTotal)

	fmt.Fprintf(w, "# HELP sendguard_rate_limits_total Cuentas con rate-limit aplicado\n")
	fmt.Fprintf(w, "# TYPE sendguard_rate_limits_total counter\n")
	fmt.Fprintf(w, "sendguard_rate_limits_total %d\n\n", enfStats.RateLimitsTotal)

	fmt.Fprintf(w, "# HELP sendguard_blocked_ips_active IPs actualmente bloqueadas\n")
	fmt.Fprintf(w, "# TYPE sendguard_blocked_ips_active gauge\n")
	fmt.Fprintf(w, "sendguard_blocked_ips_active %d\n", len(blocked))
}

func (s *Server) handleUnblock(w http.ResponseWriter, r *http.Request) {
	ip := r.PathValue("ip")
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "se requiere IPv4 válida"})
		return
	}
	if err := s.deps.Enforcer.Unblock(r.Context(), ip); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"unblocked": ip})
}

func (s *Server) handleBlock(w http.ResponseWriter, r *http.Request) {
	ip := r.PathValue("ip")
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "se requiere IPv4 válida"})
		return
	}
	if err := s.deps.Enforcer.Block(r.Context(), ip); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"blocked": ip})
}

// --- nuevos handlers ---

type urbanJSON struct {
	IP            string `json:"ip"`
	Country       string `json:"country,omitempty"`
	AbuseScore    int    `json:"abuse_score,omitempty"`
	TotalReports  int    `json:"total_reports,omitempty"`
	IsWhitelisted bool   `json:"is_whitelisted,omitempty"`
	CountryCode   string `json:"country_code,omitempty"`
	AbuseError    string `json:"abuse_error,omitempty"`
}

func (s *Server) handleUrban(w http.ResponseWriter, r *http.Request) {
	ip := r.PathValue("ip")
	if net.ParseIP(ip) == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "IP inválida"})
		return
	}

	resp := urbanJSON{IP: ip}

	if s.deps.GeoIP != nil {
		resp.Country = s.deps.GeoIP.Country(ip)
	}

	if s.deps.AbuseIPDB != nil {
		report, err := s.deps.AbuseIPDB.Check(r.Context(), ip)
		if err != nil {
			slog.Warn("api: urban: AbuseIPDB falló", "ip", ip, "error", err)
			resp.AbuseError = err.Error()
		} else {
			resp.AbuseScore = report.AbuseScore
			resp.TotalReports = report.TotalReports
			resp.IsWhitelisted = report.IsWhitelisted
			resp.CountryCode = report.CountryCode
			if resp.Country == "" {
				resp.Country = report.CountryCode
			}
		}
	}

	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleQueue(w http.ResponseWriter, r *http.Request) {
	if s.deps.PostfixSbin == "" {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "postfix_sbin no configurado",
		})
		return
	}

	entries, err := enforcement.ListQueue(r.Context(), s.deps.PostfixSbin, s.deps.PostfixConf)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if entries == nil {
		entries = []enforcement.QueueEntry{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"total":   len(entries),
		"entries": entries,
	})
}

func (s *Server) handleDomains(w http.ResponseWriter, r *http.Request) {
	stats := s.deps.Engine.DomainStats()
	if stats == nil {
		stats = []detection.DomainStat{}
	}
	writeJSON(w, http.StatusOK, stats)
}

func (s *Server) handleWhitelistGet(w http.ResponseWriter, r *http.Request) {
	if s.deps.Whitelist == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "whitelist no disponible",
		})
		return
	}
	ips, accounts := s.deps.Whitelist.List()
	if ips == nil {
		ips = []string{}
	}
	if accounts == nil {
		accounts = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ips":      ips,
		"accounts": accounts,
	})
}

func (s *Server) handleWhitelistAdd(w http.ResponseWriter, r *http.Request) {
	if s.deps.Whitelist == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "whitelist no disponible",
		})
		return
	}
	value := r.PathValue("value")
	if isIPOrCIDR(value) {
		if err := s.deps.Whitelist.AddIP(value); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"added_ip": value})
	} else {
		s.deps.Whitelist.AddAccount(value)
		writeJSON(w, http.StatusOK, map[string]string{"added_account": value})
	}
}

func (s *Server) handleWhitelistRemove(w http.ResponseWriter, r *http.Request) {
	if s.deps.Whitelist == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "whitelist no disponible",
		})
		return
	}
	value := r.PathValue("value")
	if isIPOrCIDR(value) {
		s.deps.Whitelist.RemoveIP(value)
		writeJSON(w, http.StatusOK, map[string]string{"removed_ip": value})
	} else {
		s.deps.Whitelist.RemoveAccount(value)
		writeJSON(w, http.StatusOK, map[string]string{"removed_account": value})
	}
}

// requireKey es un middleware que exige el header X-Api-Key cuando APIKey está configurada.
func (s *Server) requireKey(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.deps.APIKey == "" {
			next(w, r)
			return
		}
		if r.Header.Get("X-Api-Key") != s.deps.APIKey {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "API key inválida o ausente"})
			return
		}
		next(w, r)
	}
}

// --- helpers ---

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

// isIPOrCIDR retorna true si el string es una IP individual o un bloque CIDR válido.
func isIPOrCIDR(s string) bool {
	if net.ParseIP(s) != nil {
		return true
	}
	if strings.ContainsRune(s, '/') {
		_, _, err := net.ParseCIDR(s)
		return err == nil
	}
	return false
}

// engineAdapter adapta *detection.Engine a la interfaz que espera Dependencies.
type engineAdapter struct{ e *detection.Engine }

func (a engineAdapter) EventsTotal() int64                   { return a.e.EventsTotal.Load() }
func (a engineAdapter) AlertsTotal() int64                   { return a.e.AlertsTotal.Load() }
func (a engineAdapter) DomainStats() []detection.DomainStat { return a.e.DomainStats() }

// AdaptEngine envuelve un *detection.Engine para satisfacer la interfaz Engine de Dependencies.
func AdaptEngine(e *detection.Engine) interface {
	EventsTotal() int64
	AlertsTotal() int64
	DomainStats() []detection.DomainStat
} {
	return engineAdapter{e}
}
