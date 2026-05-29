// Package abuseipdb consulta la API de AbuseIPDB para obtener el confidence score
// de una IP. Se usa desde el Enforcer para enriquecer las alertas antes de notificar.
//
// Documentación: https://docs.abuseipdb.com/#check-endpoint
package abuseipdb

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// Config agrupa los parámetros del cliente.
type Config struct {
	APIKey   string        // clave de API de AbuseIPDB (requerida)
	CacheTTL time.Duration // tiempo de vida de cada entrada en caché (0 = sin caché)
	Timeout  int           // timeout HTTP en segundos (0 = default 10s)
}

// Report es la respuesta simplificada de AbuseIPDB para una IP.
type Report struct {
	IP            string
	AbuseScore    int  // 0-100: confianza de que la IP es abusiva
	TotalReports  int  // número total de reportes recibidos
	IsWhitelisted bool // si AbuseIPDB la tiene como whitelist
	CountryCode   string
}

type cacheEntry struct {
	report Report
	expiry time.Time
}

// maxCacheEntries limita el tamaño de la caché en memoria. Al superarse se eliminan
// las entradas expiradas para evitar crecimiento ilimitado ante muchas IPs distintas.
const maxCacheEntries = 10_000

// Client consulta la API de AbuseIPDB con caché en memoria.
type Client struct {
	cfg        Config
	httpClient *http.Client
	mu         sync.Mutex
	cache      map[string]cacheEntry
}

// New crea un Client con la configuración dada.
func New(cfg Config) *Client {
	timeout := time.Duration(cfg.Timeout) * time.Second
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	return &Client{
		cfg:        cfg,
		httpClient: &http.Client{Timeout: timeout},
		cache:      make(map[string]cacheEntry),
	}
}

// Check consulta AbuseIPDB por la IP dada.
// Retorna un Report con el abuse score y metadata. Usa caché si CacheTTL > 0.
// Si la consulta falla retorna error pero nunca bloquea la ejecución del Enforcer.
func (c *Client) Check(ctx context.Context, ip string) (Report, error) {
	if c.cfg.APIKey == "" {
		return Report{IP: ip}, fmt.Errorf("abuseipdb: API key no configurada")
	}

	if c.cfg.CacheTTL > 0 {
		if r, ok := c.fromCache(ip); ok {
			return r, nil
		}
	}

	report, err := c.fetch(ctx, ip)
	if err != nil {
		return Report{IP: ip}, err
	}

	if c.cfg.CacheTTL > 0 {
		c.toCache(ip, report)
	}
	return report, nil
}

// apiResponse modela la respuesta JSON de /api/v2/check.
type apiResponse struct {
	Data struct {
		IPAddress            string `json:"ipAddress"`
		AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
		TotalReports         int    `json:"totalReports"`
		IsWhitelisted        bool   `json:"isWhitelisted"`
		CountryCode          string `json:"countryCode"`
	} `json:"data"`
}

func (c *Client) fetch(ctx context.Context, ip string) (Report, error) {
	url := fmt.Sprintf("https://api.abuseipdb.com/api/v2/check?ipAddress=%s&maxAgeInDays=90", ip)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Report{IP: ip}, fmt.Errorf("abuseipdb: crear request: %w", err)
	}
	req.Header.Set("Key", c.cfg.APIKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return Report{IP: ip}, fmt.Errorf("abuseipdb: GET: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		return Report{IP: ip}, fmt.Errorf("abuseipdb: rate limit alcanzado (429)")
	}
	if resp.StatusCode != http.StatusOK {
		return Report{IP: ip}, fmt.Errorf("abuseipdb: respuesta %d", resp.StatusCode)
	}

	var ar apiResponse
	if err := json.NewDecoder(resp.Body).Decode(&ar); err != nil {
		return Report{IP: ip}, fmt.Errorf("abuseipdb: decodificar respuesta: %w", err)
	}

	return Report{
		IP:            ar.Data.IPAddress,
		AbuseScore:    ar.Data.AbuseConfidenceScore,
		TotalReports:  ar.Data.TotalReports,
		IsWhitelisted: ar.Data.IsWhitelisted,
		CountryCode:   ar.Data.CountryCode,
	}, nil
}

func (c *Client) fromCache(ip string) (Report, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.cache[ip]
	if !ok || time.Now().After(e.expiry) {
		return Report{}, false
	}
	return e.report, true
}

func (c *Client) toCache(ip string, r Report) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.cache) >= maxCacheEntries {
		now := time.Now()
		for k, e := range c.cache {
			if now.After(e.expiry) {
				delete(c.cache, k)
			}
		}
	}
	c.cache[ip] = cacheEntry{report: r, expiry: time.Now().Add(c.cfg.CacheTTL)}
}
