package geoip_test

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/perulinux/sendguard/internal/geoip"
)

// newAPIResolver crea un Resolver en modo HTTP API apuntando al servidor de test.
func newAPIResolver(srv *httptest.Server) *geoip.Resolver {
	return geoip.New("", srv.URL, "", time.Hour)
}

// jsonSrv devuelve un servidor HTTP que responde siempre con el JSON dado.
func jsonSrv(body string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(body)) //nolint:errcheck
	}))
}

func TestCountryPublicIP(t *testing.T) {
	srv := jsonSrv(`{"ip":"1.2.3.4","country":"PE"}`)
	defer srv.Close()

	r := newAPIResolver(srv)
	if got := r.Country("1.2.3.4"); got != "PE" {
		t.Errorf("Country: got %q, want %q", got, "PE")
	}
}

func TestCountryNormalizesLowercase(t *testing.T) {
	srv := jsonSrv(`{"country":"pe"}`)
	defer srv.Close()

	r := newAPIResolver(srv)
	if got := r.Country("1.2.3.4"); got != "PE" {
		t.Errorf("normalización a mayúsculas: got %q, want %q", got, "PE")
	}
}

func TestCountryPlainTextResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("BR\n")) //nolint:errcheck
	}))
	defer srv.Close()

	r := newAPIResolver(srv)
	if got := r.Country("1.2.3.4"); got != "BR" {
		t.Errorf("respuesta texto plano: got %q, want %q", got, "BR")
	}
}

func TestCountryPrivateIPs(t *testing.T) {
	// IPs privadas deben retornar "" sin consultar la API ni la DB.
	r := geoip.New("", "http://127.0.0.1:0", "", time.Hour)

	privateIPs := []string{
		"10.0.0.1",
		"10.255.255.255",
		"172.16.0.1",
		"172.31.255.255",
		"192.168.0.1",
		"192.168.255.255",
		"127.0.0.1",
		"127.0.0.2",
		"169.254.1.1",
		"100.64.0.1",
		"100.127.255.255",
	}
	for _, ip := range privateIPs {
		if got := r.Country(ip); got != "" {
			t.Errorf("IP privada %s: got %q, want %q", ip, got, "")
		}
	}
}

func TestCountryCacheHit(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Write([]byte(`{"country":"US"}`)) //nolint:errcheck
	}))
	defer srv.Close()

	r := newAPIResolver(srv)
	r.Country("8.8.8.8")
	r.Country("8.8.8.8")

	if callCount != 1 {
		t.Errorf("cache hit: se esperaba 1 llamada a la API, got %d", callCount)
	}
}

func TestCountryCacheMissAfterTTL(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Write([]byte(`{"country":"US"}`)) //nolint:errcheck
	}))
	defer srv.Close()

	r := geoip.New("", srv.URL, "", time.Nanosecond)
	r.Country("8.8.8.8")
	time.Sleep(time.Millisecond)
	r.Country("8.8.8.8")

	if callCount != 2 {
		t.Errorf("cache expirado: se esperaban 2 llamadas a la API, got %d", callCount)
	}
}

func TestCountryFailureNotCached(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Write([]byte(`{"country":"CN"}`)) //nolint:errcheck
	}))
	defer srv.Close()

	r := newAPIResolver(srv)
	first := r.Country("1.2.3.4")
	second := r.Country("1.2.3.4")

	if first != "" {
		t.Errorf("primer intento (fallo API): got %q, want %q", first, "")
	}
	if second != "CN" {
		t.Errorf("segundo intento (reintento): got %q, want %q", second, "CN")
	}
	if callCount != 2 {
		t.Errorf("se esperaban 2 llamadas a la API, got %d", callCount)
	}
}

func TestCountryAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	r := newAPIResolver(srv)
	if got := r.Country("1.2.3.4"); got != "" {
		t.Errorf("error HTTP 500: got %q, want %q", got, "")
	}
}

func TestCountryInvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not-valid-json-or-two-chars")) //nolint:errcheck
	}))
	defer srv.Close()

	r := newAPIResolver(srv)
	if got := r.Country("1.2.3.4"); got != "" {
		t.Errorf("JSON inválido: got %q, want %q", got, "")
	}
}

func TestCountryInvalidCountryLength(t *testing.T) {
	srv := jsonSrv(`{"country":"PER"}`)
	defer srv.Close()

	r := newAPIResolver(srv)
	if got := r.Country("1.2.3.4"); got != "" {
		t.Errorf("país de 3 letras: got %q, want %q", got, "")
	}
}

func TestCountryRequestURL(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Write([]byte(`{"country":"DE"}`)) //nolint:errcheck
	}))
	defer srv.Close()

	r := newAPIResolver(srv)
	r.Country("5.6.7.8")

	if gotPath != "/5.6.7.8" {
		t.Errorf("URL path: got %q, want %q", gotPath, "/5.6.7.8")
	}
}

func TestCountryConcurrentSafe(t *testing.T) {
	srv := jsonSrv(`{"country":"JP"}`)
	defer srv.Close()

	r := newAPIResolver(srv)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.Country("9.9.9.9")
		}()
	}
	wg.Wait()
}

func TestCountryDBPathInvalidFallsBackToAPI(t *testing.T) {
	// DB path inexistente → debe caer al HTTP API sin error fatal.
	srv := jsonSrv(`{"country":"AR"}`)
	defer srv.Close()

	r := geoip.New("/tmp/no-existe.mmdb", srv.URL, "", time.Hour)
	if got := r.Country("1.2.3.4"); got != "AR" {
		t.Errorf("fallback a API cuando DB no existe: got %q, want %q", got, "AR")
	}
}
