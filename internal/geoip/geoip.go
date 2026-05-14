// Package geoip resuelve direcciones IPv4 a códigos de país (ISO 3166-1 alpha-2)
// usando la API de ipinfo.io/lite. Los resultados se cachean en memoria con un TTL
// configurable para minimizar llamadas a la API.
//
// Las búsquedas fallidas (API caída, IP privada, respuesta inesperada) retornan ""
// y NO se cachean, de modo que el próximo intento vuelve a intentar la resolución.
//
// Thread-safe: puede ser llamado concurrentemente desde múltiples goroutines.
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
)

const (
	httpTimeout    = 3 * time.Second // timeout por request a la API
	maxBodyBytes   = 256             // límite de lectura de la respuesta
)

// Resolver resuelve IPs a países con caché en memoria.
type Resolver struct {
	apiURL     string
	token      string
	cacheTTL   time.Duration
	httpClient *http.Client
	mu         sync.RWMutex
	cache      map[string]cacheEntry
}

type cacheEntry struct {
	country string
	expiry  time.Time
}

// New crea un Resolver. apiURL es la URL base (ej: "https://ipinfo.io").
// token es opcional; si no está vacío se envía como "Authorization: Bearer <token>".
// cacheTTL es el tiempo de vida de cada entrada en caché.
func New(apiURL, token string, cacheTTL time.Duration) *Resolver {
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

// Country retorna el código de país ISO 3166-1 alpha-2 para la IP dada (ej: "PE", "US").
// Retorna "" si la IP es privada, la resolución falla, o la respuesta es inesperada.
// Los resultados exitosos se cachean por cacheTTL.
func (r *Resolver) Country(ip string) string {
	if isPrivateIP(ip) {
		return ""
	}

	// Lectura con RLock (caso frecuente: cache hit)
	r.mu.RLock()
	if entry, ok := r.cache[ip]; ok && time.Now().Before(entry.expiry) {
		r.mu.RUnlock()
		return entry.country
	}
	r.mu.RUnlock()

	// Cache miss: consultar API
	country := r.lookup(ip)
	if country == "" {
		return "" // no cachear fallos para reintentar en la próxima llamada
	}

	r.mu.Lock()
	r.cache[ip] = cacheEntry{
		country: country,
		expiry:  time.Now().Add(r.cacheTTL),
	}
	r.mu.Unlock()

	slog.Debug("geoip: IP resuelta", "ip", ip, "country", country)
	return country
}

// lookup hace una petición HTTP a la API y retorna el código de país o "".
func (r *Resolver) lookup(ip string) string {
	url := r.apiURL + "/" + ip

	req, err := http.NewRequest(http.MethodGet, url, nil) //nolint:noctx
	if err != nil {
		return ""
	}
	if r.token != "" {
		req.Header.Set("Authorization", "Bearer "+r.token)
	}

	resp, err := r.httpClient.Do(req)
	if err != nil {
		slog.Warn("geoip: error al consultar API", "ip", ip, "error", err)
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		slog.Warn("geoip: respuesta inesperada de API", "ip", ip, "status", resp.StatusCode)
		return ""
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return ""
	}

	// ipinfo.io retorna JSON: {"ip":"...","country":"PE",...}
	var result struct {
		Country string `json:"country"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		// Algunos endpoints retornan solo el código como texto plano ("PE\n")
		plain := strings.TrimSpace(string(body))
		if len(plain) == 2 {
			return strings.ToUpper(plain)
		}
		slog.Warn("geoip: respuesta no parseable", "ip", ip, "body", string(body))
		return ""
	}

	if len(result.Country) != 2 {
		return ""
	}
	return strings.ToUpper(result.Country)
}

// isPrivateIP retorna true para IPs de redes privadas/reservadas.
// Estas IPs no tienen sentido en una consulta GeoIP.
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

// privateRanges lista los rangos de IPs privadas y reservadas según RFC 1918 / RFC 5735.
var privateRanges = func() []*net.IPNet {
	ranges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16", // link-local
		"100.64.0.0/10",  // shared address space (RFC 6598)
	}
	nets := make([]*net.IPNet, 0, len(ranges))
	for _, r := range ranges {
		_, cidr, _ := net.ParseCIDR(r)
		nets = append(nets, cidr)
	}
	return nets
}()
