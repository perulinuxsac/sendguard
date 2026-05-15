// Package geoip resuelve direcciones IPv4 a códigos de país (ISO 3166-1 alpha-2).
//
// Dos modos de operación (seleccionados en New según la configuración):
//   - DB local (MaxMind GeoLite2-Country.mmdb): sin red, sin rate-limit, microsegundos.
//   - HTTP API (ipinfo.io u otro): fallback cuando no hay DB configurada.
//
// Las búsquedas HTTP fallidas no se cachean para reintentar en el próximo ciclo.
// Thread-safe.
package geoip

import (
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/geoip2-golang"
)

const (
	httpTimeout  = 3 * time.Second
	maxBodyBytes = 1024
)

// Resolver resuelve IPs a códigos de país.
type Resolver struct {
	// Modo DB local
	db *geoip2.Reader

	// Modo HTTP API
	apiURL     string
	token      string
	cacheTTL   time.Duration
	httpClient *http.Client
	mu         sync.RWMutex
	cache      map[string]cacheEntry
}

type cacheEntry struct {
	country string
	org     string // ej: "AS8075 MICROSOFT-CORP-MSN-AS-BLOCK"
	expiry  time.Time
}

// New crea un Resolver. Si dbPath no está vacío y el archivo existe, usa la DB
// local (MaxMind GeoLite2-Country.mmdb). En caso contrario usa el HTTP API.
// apiURL y token solo aplican al modo HTTP.
func New(dbPath, apiURL, token string, cacheTTL time.Duration) *Resolver {
	if dbPath != "" {
		db, err := geoip2.Open(dbPath)
		if err != nil {
			slog.Warn("geoip: no se pudo abrir DB local, usando HTTP API", "path", dbPath, "error", err)
		} else {
			slog.Info("geoip: usando base de datos local", "path", dbPath)
			return &Resolver{db: db}
		}
	}
	return &Resolver{
		apiURL:   strings.TrimRight(apiURL, "/"),
		token:    token,
		cacheTTL: cacheTTL,
		httpClient: &http.Client{
			Timeout: httpTimeout,
		},
		cache: make(map[string]cacheEntry),
	}
}

// Close libera recursos de la DB local (no-op en modo HTTP).
func (r *Resolver) Close() {
	if r.db != nil {
		r.db.Close()
	}
}

// Country retorna el código ISO 3166-1 alpha-2 para la IP dada (ej: "PE", "US").
// Retorna "" para IPs privadas, fallos de resolución o respuestas inesperadas.
func (r *Resolver) Country(ip string) string {
	if isPrivateIP(ip) {
		return ""
	}
	if r.db != nil {
		return r.lookupDB(ip)
	}
	return r.lookupAPI(ip)
}

func (r *Resolver) lookupDB(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	record, err := r.db.Country(parsed)
	if err != nil {
		slog.Warn("geoip: error en DB local", "ip", ip, "error", err)
		return ""
	}
	country := strings.ToUpper(record.Country.IsoCode)
	if len(country) != 2 {
		return ""
	}
	return country
}

// Org retorna el string de organización/ASN para la IP (ej: "AS8075 MICROSOFT-CORP-MSN-AS-BLOCK").
// Solo disponible en modo HTTP API; retorna "" en modo DB local o si falla la resolución.
func (r *Resolver) Org(ip string) string {
	if isPrivateIP(ip) || r.db != nil {
		return ""
	}
	r.mu.RLock()
	if entry, ok := r.cache[ip]; ok && time.Now().Before(entry.expiry) {
		r.mu.RUnlock()
		return entry.org
	}
	r.mu.RUnlock()
	r.lookupAPI(ip) // popula caché con country + org
	r.mu.RLock()
	org := r.cache[ip].org
	r.mu.RUnlock()
	return org
}

func (r *Resolver) lookupAPI(ip string) string {
	r.mu.RLock()
	if entry, ok := r.cache[ip]; ok && time.Now().Before(entry.expiry) {
		r.mu.RUnlock()
		return entry.country
	}
	r.mu.RUnlock()

	country, org := r.fetchAPI(ip)
	if country == "" {
		return ""
	}

	r.mu.Lock()
	r.cache[ip] = cacheEntry{
		country: country,
		org:     org,
		expiry:  time.Now().Add(r.cacheTTL),
	}
	r.mu.Unlock()

	slog.Debug("geoip: IP resuelta via API", "ip", ip, "country", country, "org", org)
	return country
}

func (r *Resolver) fetchAPI(ip string) (country, org string) {
	req, err := http.NewRequest(http.MethodGet, r.apiURL+"/"+ip, nil) //nolint:noctx
	if err != nil {
		return "", ""
	}
	if r.token != "" {
		req.Header.Set("Authorization", "Bearer "+r.token)
	}

	resp, err := r.httpClient.Do(req)
	if err != nil {
		slog.Warn("geoip: error al consultar API", "ip", ip, "error", err)
		return "", ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		slog.Warn("geoip: respuesta inesperada de API", "ip", ip, "status", resp.StatusCode)
		return "", ""
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return "", ""
	}

	var result struct {
		Country string `json:"country"`
		Org     string `json:"org"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		plain := strings.TrimSpace(string(body))
		if len(plain) == 2 {
			return strings.ToUpper(plain), ""
		}
		slog.Warn("geoip: respuesta no parseable", "ip", ip, "body", string(body))
		return "", ""
	}

	if len(result.Country) != 2 {
		return "", ""
	}
	return strings.ToUpper(result.Country), result.Org
}

func isPrivateIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return true
	}
	for _, cidr := range privateRanges {
		if cidr.Contains(parsed) {
			return true
		}
	}
	return false
}

var privateRanges = func() []*net.IPNet {
	ranges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"100.64.0.0/10",
	}
	nets := make([]*net.IPNet, 0, len(ranges))
	for _, r := range ranges {
		_, cidr, _ := net.ParseCIDR(r)
		nets = append(nets, cidr)
	}
	return nets
}()
