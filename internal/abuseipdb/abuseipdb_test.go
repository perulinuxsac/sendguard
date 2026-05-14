package abuseipdb

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func makeServer(t *testing.T, score int, totalReports int, statusCode int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if statusCode != http.StatusOK {
			w.WriteHeader(statusCode)
			return
		}
		resp := map[string]any{
			"data": map[string]any{
				"ipAddress":            r.URL.Query().Get("ipAddress"),
				"abuseConfidenceScore": score,
				"totalReports":         totalReports,
				"isWhitelisted":        false,
				"countryCode":          "US",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
}

func newClient(url string) *Client {
	c := New(Config{APIKey: "test-key", CacheTTL: time.Minute})
	// Redirigir todas las peticiones al servidor de test preservando la query string.
	c.httpClient = &http.Client{
		Timeout: 5 * time.Second,
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			r2, _ := http.NewRequestWithContext(r.Context(), r.Method, url+r.URL.RequestURI(), r.Body)
			r2.Header = r.Header
			return http.DefaultTransport.RoundTrip(r2)
		}),
	}
	return c
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestCheckRetornaScore(t *testing.T) {
	srv := makeServer(t, 85, 10, http.StatusOK)
	defer srv.Close()

	c := newClient(srv.URL)
	report, err := c.Check(context.Background(), "1.2.3.4")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if report.AbuseScore != 85 {
		t.Errorf("AbuseScore: got %d, want 85", report.AbuseScore)
	}
	if report.TotalReports != 10 {
		t.Errorf("TotalReports: got %d, want 10", report.TotalReports)
	}
	if report.CountryCode != "US" {
		t.Errorf("CountryCode: got %q, want US", report.CountryCode)
	}
}

func TestCheckEnviaAPIKeyEnHeader(t *testing.T) {
	var gotKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("Key")
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"ipAddress": "1.2.3.4", "abuseConfidenceScore": 0,
			"totalReports": 0, "isWhitelisted": false, "countryCode": "",
		}})
	}))
	defer srv.Close()

	c := newClient(srv.URL)
	c.Check(context.Background(), "1.2.3.4")

	if gotKey != "test-key" {
		t.Errorf("header Key: got %q, want test-key", gotKey)
	}
}

func TestCheckError4xx(t *testing.T) {
	srv := makeServer(t, 0, 0, http.StatusUnauthorized)
	defer srv.Close()

	c := newClient(srv.URL)
	_, err := c.Check(context.Background(), "1.2.3.4")
	if err == nil {
		t.Error("respuesta 401 debe retornar error")
	}
}

func TestCheckRateLimit429(t *testing.T) {
	srv := makeServer(t, 0, 0, http.StatusTooManyRequests)
	defer srv.Close()

	c := newClient(srv.URL)
	_, err := c.Check(context.Background(), "1.2.3.4")
	if err == nil {
		t.Error("respuesta 429 debe retornar error")
	}
}

func TestCheckSinAPIKey(t *testing.T) {
	c := New(Config{APIKey: ""})
	_, err := c.Check(context.Background(), "1.2.3.4")
	if err == nil {
		t.Error("sin API key debe retornar error")
	}
}

func TestCacheEvitaSegundaConsulta(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"ipAddress": "1.2.3.4", "abuseConfidenceScore": 50,
			"totalReports": 5, "isWhitelisted": false, "countryCode": "DE",
		}})
	}))
	defer srv.Close()

	c := newClient(srv.URL)
	c.cfg.CacheTTL = time.Minute

	c.Check(context.Background(), "1.2.3.4")
	c.Check(context.Background(), "1.2.3.4")
	c.Check(context.Background(), "1.2.3.4")

	if calls != 1 {
		t.Errorf("con caché: got %d llamadas al servidor, want 1", calls)
	}
}

func TestCacheExpirada(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"ipAddress": "1.2.3.4", "abuseConfidenceScore": 0,
			"totalReports": 0, "isWhitelisted": false, "countryCode": "",
		}})
	}))
	defer srv.Close()

	c := newClient(srv.URL)
	c.cfg.CacheTTL = time.Millisecond // expira casi inmediatamente

	c.Check(context.Background(), "1.2.3.4")
	time.Sleep(5 * time.Millisecond)
	c.Check(context.Background(), "1.2.3.4")

	if calls != 2 {
		t.Errorf("caché expirada: got %d llamadas, want 2", calls)
	}
}

func TestContextCancelado(t *testing.T) {
	srv := makeServer(t, 0, 0, http.StatusOK)
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	c := newClient(srv.URL)
	c.cfg.CacheTTL = 0 // sin caché para forzar la petición HTTP
	_, err := c.Check(ctx, "1.2.3.4")
	if err == nil {
		t.Error("contexto cancelado debe retornar error")
	}
}

func TestCheckIPEnRespuesta(t *testing.T) {
	srv := makeServer(t, 30, 3, http.StatusOK)
	defer srv.Close()

	c := newClient(srv.URL)
	report, err := c.Check(context.Background(), "9.8.7.6")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	// El servidor de test devuelve la IP de la query string.
	if report.IP == "" {
		t.Error("IP en report no debe estar vacía")
	}
}
