package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/perulinux/sendguard/internal/abuseipdb"
	"github.com/perulinux/sendguard/internal/api"
	"github.com/perulinux/sendguard/internal/detection"
	"github.com/perulinux/sendguard/internal/enforcement"
)

// --- mocks ---

type mockEnforcer struct {
	blocked       []enforcement.BlockedIPInfo
	stats         enforcement.EnforcerStats
	unblockCalled string
	unblockErr    error
	blockCalled   string
	blockErr      error
}

func (m *mockEnforcer) BlockedIPs() []enforcement.BlockedIPInfo            { return m.blocked }
func (m *mockEnforcer) SuspendedAccounts() []enforcement.SuspendedAcctInfo { return nil }
func (m *mockEnforcer) Stats() enforcement.EnforcerStats                   { return m.stats }
func (m *mockEnforcer) Unblock(_ context.Context, ip string) error {
	m.unblockCalled = ip
	return m.unblockErr
}
func (m *mockEnforcer) Block(_ context.Context, ip string, _ int) error {
	m.blockCalled = ip
	return m.blockErr
}
func (m *mockEnforcer) IsBlocked(_ string) bool { return false }
func (m *mockEnforcer) GetBlockedIP(ip string) (enforcement.BlockedIPInfo, bool) {
	for _, b := range m.blocked {
		if b.IP == ip {
			return b, true
		}
	}
	return enforcement.BlockedIPInfo{}, false
}
func (m *mockEnforcer) Unsuspend(_ context.Context, _ string) error { return nil }

type mockEngine struct {
	events  int64
	alerts  int64
	domains []detection.DomainStat
}

func (m *mockEngine) EventsTotal() int64                  { return m.events }
func (m *mockEngine) AlertsTotal() int64                  { return m.alerts }
func (m *mockEngine) DomainStats() []detection.DomainStat { return m.domains }
func (m *mockEngine) ModuleStats() []detection.ModuleStat { return nil }

func newTestServer(enf *mockEnforcer, eng *mockEngine) *api.Server {
	return api.New("127.0.0.1:0", api.Dependencies{
		Enforcer:  enf,
		Engine:    eng,
		StartTime: time.Now().Add(-5 * time.Minute),
	})
}

func newTestServerWithKey(enf *mockEnforcer, eng *mockEngine, key string) *api.Server {
	return api.New("127.0.0.1:0", api.Dependencies{
		Enforcer:  enf,
		Engine:    eng,
		StartTime: time.Now().Add(-5 * time.Minute),
		APIKey:    key,
	})
}

func do(t *testing.T, srv *api.Server, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)
	return rr
}

func doWithKey(t *testing.T, srv *api.Server, method, path, key string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if key != "" {
		req.Header.Set("X-Api-Key", key)
	}
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)
	return rr
}

// --- tests ---

func TestHealthOK(t *testing.T) {
	srv := newTestServer(&mockEnforcer{}, &mockEngine{})
	rr := do(t, srv, http.MethodGet, "/health")

	if rr.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", rr.Code)
	}
	var body map[string]string
	json.NewDecoder(rr.Body).Decode(&body)
	if body["status"] != "ok" {
		t.Errorf("status field: got %q, want ok", body["status"])
	}
}

func TestHealthContentType(t *testing.T) {
	srv := newTestServer(&mockEnforcer{}, &mockEngine{})
	rr := do(t, srv, http.MethodGet, "/health")
	ct := rr.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type: got %q, want application/json", ct)
	}
}

func TestStatusSinBloqueadas(t *testing.T) {
	srv := newTestServer(&mockEnforcer{}, &mockEngine{events: 100, alerts: 3})
	rr := do(t, srv, http.MethodGet, "/status")

	if rr.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", rr.Code)
	}
	var body map[string]any
	json.NewDecoder(rr.Body).Decode(&body)

	ips := body["blocked_ips"].([]any)
	if len(ips) != 0 {
		t.Errorf("blocked_ips: got %d, want 0", len(ips))
	}
}

func TestStatusConBloqueadas(t *testing.T) {
	enf := &mockEnforcer{
		blocked: []enforcement.BlockedIPInfo{
			{IP: "1.2.3.4", Expiry: time.Now().Add(30 * time.Minute), Module: "auth_failed"},
			{IP: "5.6.7.8", Expiry: time.Now().Add(10 * time.Minute), Module: "domain_discovery"},
		},
		stats: enforcement.EnforcerStats{BlocksTotal: 2},
	}
	srv := newTestServer(enf, &mockEngine{events: 500, alerts: 2})
	rr := do(t, srv, http.MethodGet, "/status")

	var body map[string]any
	json.NewDecoder(rr.Body).Decode(&body)

	ips := body["blocked_ips"].([]any)
	if len(ips) != 2 {
		t.Fatalf("blocked_ips: got %d, want 2", len(ips))
	}
}

func TestStatusStatsPresentes(t *testing.T) {
	enf := &mockEnforcer{
		stats: enforcement.EnforcerStats{
			BlocksTotal:      5,
			SuspensionsTotal: 2,
			RateLimitsTotal:  1,
		},
	}
	srv := newTestServer(enf, &mockEngine{events: 1000, alerts: 8})
	rr := do(t, srv, http.MethodGet, "/status")

	var body map[string]any
	json.NewDecoder(rr.Body).Decode(&body)

	stats := body["stats"].(map[string]any)
	if int(stats["events_total"].(float64)) != 1000 {
		t.Errorf("events_total: got %v, want 1000", stats["events_total"])
	}
	if int(stats["blocks_total"].(float64)) != 5 {
		t.Errorf("blocks_total: got %v, want 5", stats["blocks_total"])
	}
}

func TestMetricsContieneContadores(t *testing.T) {
	enf := &mockEnforcer{
		stats: enforcement.EnforcerStats{BlocksTotal: 7},
		blocked: []enforcement.BlockedIPInfo{
			{IP: "1.1.1.1", Expiry: time.Now().Add(time.Hour), Module: "auth_failed"},
		},
	}
	srv := newTestServer(enf, &mockEngine{events: 42})
	rr := do(t, srv, http.MethodGet, "/metrics")

	if rr.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	for _, want := range []string{
		"sendguard_events_total 42",
		"sendguard_blocks_total 7",
		"sendguard_blocked_ips_active 1",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics body no contiene %q:\n%s", want, body)
		}
	}
}

func TestMetricsContentType(t *testing.T) {
	srv := newTestServer(&mockEnforcer{}, &mockEngine{})
	rr := do(t, srv, http.MethodGet, "/metrics")
	ct := rr.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("Content-Type: got %q, want text/plain", ct)
	}
}

func TestUnblockValido(t *testing.T) {
	enf := &mockEnforcer{}
	srv := newTestServer(enf, &mockEngine{})
	rr := do(t, srv, http.MethodDelete, "/blocked/1.2.3.4")

	if rr.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", rr.Code)
	}
	if enf.unblockCalled != "1.2.3.4" {
		t.Errorf("Unblock llamado con %q, want 1.2.3.4", enf.unblockCalled)
	}
	var body map[string]string
	json.NewDecoder(rr.Body).Decode(&body)
	if body["unblocked"] != "1.2.3.4" {
		t.Errorf("respuesta unblocked: got %q, want 1.2.3.4", body["unblocked"])
	}
}

func TestUnblockIPInvalida(t *testing.T) {
	srv := newTestServer(&mockEnforcer{}, &mockEngine{})
	rr := do(t, srv, http.MethodDelete, "/blocked/no-es-una-ip")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400", rr.Code)
	}
}

func TestUnblockIPv6Rechazada(t *testing.T) {
	srv := newTestServer(&mockEnforcer{}, &mockEngine{})
	rr := do(t, srv, http.MethodDelete, "/blocked/::1")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("IPv6 debe retornar 400, got %d", rr.Code)
	}
}

func TestMetodoNoPermitido(t *testing.T) {
	srv := newTestServer(&mockEnforcer{}, &mockEngine{})
	rr := do(t, srv, http.MethodPost, "/health")
	if rr.Code == http.StatusOK {
		t.Error("POST /health no debe retornar 200")
	}
}

// --- Block endpoint ---

func TestBlockValido(t *testing.T) {
	enf := &mockEnforcer{}
	srv := newTestServer(enf, &mockEngine{})
	rr := do(t, srv, http.MethodPost, "/blocked/5.6.7.8")

	if rr.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", rr.Code)
	}
	if enf.blockCalled != "5.6.7.8" {
		t.Errorf("Block llamado con %q, want 5.6.7.8", enf.blockCalled)
	}
	var body map[string]string
	json.NewDecoder(rr.Body).Decode(&body)
	if body["blocked"] != "5.6.7.8" {
		t.Errorf("respuesta blocked: got %q, want 5.6.7.8", body["blocked"])
	}
}

func TestBlockIPInvalida(t *testing.T) {
	srv := newTestServer(&mockEnforcer{}, &mockEngine{})
	rr := do(t, srv, http.MethodPost, "/blocked/no-es-ip")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400", rr.Code)
	}
}

// --- Autenticación con API key ---

func TestRequireKeyConKeyCorrecta(t *testing.T) {
	enf := &mockEnforcer{}
	srv := newTestServerWithKey(enf, &mockEngine{}, "secret-key")
	rr := doWithKey(t, srv, http.MethodDelete, "/blocked/1.2.3.4", "secret-key")

	if rr.Code != http.StatusOK {
		t.Fatalf("key correcta: got %d, want 200", rr.Code)
	}
}

func TestRequireKeyConKeyIncorrecta(t *testing.T) {
	srv := newTestServerWithKey(&mockEnforcer{}, &mockEngine{}, "secret-key")
	rr := doWithKey(t, srv, http.MethodDelete, "/blocked/1.2.3.4", "wrong-key")

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("key incorrecta: got %d, want 401", rr.Code)
	}
}

func TestRequireKeySinHeader(t *testing.T) {
	srv := newTestServerWithKey(&mockEnforcer{}, &mockEngine{}, "secret-key")
	rr := do(t, srv, http.MethodDelete, "/blocked/1.2.3.4")

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("sin header: got %d, want 401", rr.Code)
	}
}

func TestRequireKeySinConfigNoBloquea(t *testing.T) {
	// Sin APIKey configurada, el endpoint es libre (retrocompatible).
	enf := &mockEnforcer{}
	srv := newTestServer(enf, &mockEngine{}) // APIKey = ""
	rr := do(t, srv, http.MethodDelete, "/blocked/1.2.3.4")

	if rr.Code != http.StatusOK {
		t.Fatalf("sin api_key configurada: got %d, want 200", rr.Code)
	}
}

func TestRequireKeyNoAfectaHealthNiMetrics(t *testing.T) {
	// /health y /metrics deben responder 200 aunque la key sea inválida.
	srv := newTestServerWithKey(&mockEnforcer{}, &mockEngine{}, "secret-key")

	for _, path := range []string{"/health", "/metrics", "/status"} {
		rr := do(t, srv, http.MethodGet, path)
		if rr.Code != http.StatusOK {
			t.Errorf("GET %s sin key: got %d, want 200 (endpoint público)", path, rr.Code)
		}
	}
}

// ── mocks adicionales ─────────────────────────────────────────────────────────

type mockGeoIP struct{ country string }

func (m *mockGeoIP) Country(_ string) string { return m.country }

type mockAbuseIPDB struct {
	report abuseipdb.Report
	err    error
}

func (m *mockAbuseIPDB) Check(_ context.Context, _ string) (abuseipdb.Report, error) {
	return m.report, m.err
}

type mockWhitelist struct {
	ips      []string
	accounts []string
	addIPErr error
}

func (m *mockWhitelist) List() ([]string, []string) { return m.ips, m.accounts }
func (m *mockWhitelist) AddIP(ip string) error      { m.ips = append(m.ips, ip); return m.addIPErr }
func (m *mockWhitelist) RemoveIP(ip string)         { /* simplificado para tests */ }
func (m *mockWhitelist) AddAccount(a string)        { m.accounts = append(m.accounts, a) }
func (m *mockWhitelist) RemoveAccount(a string)     { /* simplificado para tests */ }

func newFullTestServer(enf *mockEnforcer, eng *mockEngine, opts ...func(*api.Dependencies)) *api.Server {
	deps := api.Dependencies{
		Enforcer:  enf,
		Engine:    eng,
		StartTime: time.Now().Add(-5 * time.Minute),
	}
	for _, o := range opts {
		o(&deps)
	}
	return api.New("127.0.0.1:0", deps)
}

// ── /urban ────────────────────────────────────────────────────────────────────

func TestUrbanIPInvalida(t *testing.T) {
	srv := newTestServer(&mockEnforcer{}, &mockEngine{})
	rr := do(t, srv, http.MethodGet, "/urban/no-es-ip")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("IP inválida: got %d, want 400", rr.Code)
	}
}

func TestUrbanSinFuentesConfiguradas(t *testing.T) {
	srv := newTestServer(&mockEnforcer{}, &mockEngine{})
	rr := do(t, srv, http.MethodGet, "/urban/1.2.3.4")
	if rr.Code != http.StatusOK {
		t.Fatalf("sin fuentes: got %d, want 200", rr.Code)
	}
	var body map[string]any
	json.NewDecoder(rr.Body).Decode(&body)
	if body["ip"] != "1.2.3.4" {
		t.Errorf("ip field: got %v, want 1.2.3.4", body["ip"])
	}
}

func TestUrbanConGeoIP(t *testing.T) {
	srv := newFullTestServer(&mockEnforcer{}, &mockEngine{}, func(d *api.Dependencies) {
		d.GeoIP = &mockGeoIP{country: "PE"}
	})
	rr := do(t, srv, http.MethodGet, "/urban/1.2.3.4")

	var body map[string]any
	json.NewDecoder(rr.Body).Decode(&body)
	if body["country"] != "PE" {
		t.Errorf("country: got %v, want PE", body["country"])
	}
}

func TestUrbanConAbuseIPDB(t *testing.T) {
	srv := newFullTestServer(&mockEnforcer{}, &mockEngine{}, func(d *api.Dependencies) {
		d.AbuseIPDB = &mockAbuseIPDB{
			report: abuseipdb.Report{AbuseScore: 85, TotalReports: 10, CountryCode: "CN"},
		}
	})
	rr := do(t, srv, http.MethodGet, "/urban/2.2.2.2")
	if rr.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", rr.Code)
	}
	var body map[string]any
	json.NewDecoder(rr.Body).Decode(&body)
	if int(body["abuse_score"].(float64)) != 85 {
		t.Errorf("abuse_score: got %v, want 85", body["abuse_score"])
	}
}

func TestUrbanAbuseIPDBError(t *testing.T) {
	srv := newFullTestServer(&mockEnforcer{}, &mockEngine{}, func(d *api.Dependencies) {
		d.AbuseIPDB = &mockAbuseIPDB{err: errors.New("api down")}
	})
	rr := do(t, srv, http.MethodGet, "/urban/3.3.3.3")
	if rr.Code != http.StatusOK {
		t.Fatalf("error de abuseipdb no debe cambiar status: got %d", rr.Code)
	}
	var body map[string]any
	json.NewDecoder(rr.Body).Decode(&body)
	if _, ok := body["abuse_error"]; !ok {
		t.Error("debe incluir campo abuse_error cuando falla")
	}
}

// ── /queue ────────────────────────────────────────────────────────────────────

func TestQueueSinPostfixSbin(t *testing.T) {
	srv := newTestServer(&mockEnforcer{}, &mockEngine{})
	rr := do(t, srv, http.MethodGet, "/queue")
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("sin PostfixSbin: got %d, want 503", rr.Code)
	}
}

// ── /domains ──────────────────────────────────────────────────────────────────

func TestDomainsSinDatos(t *testing.T) {
	srv := newTestServer(&mockEnforcer{}, &mockEngine{})
	rr := do(t, srv, http.MethodGet, "/domains")
	if rr.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", rr.Code)
	}
	var body []any
	json.NewDecoder(rr.Body).Decode(&body)
	if len(body) != 0 {
		t.Errorf("esperado array vacío, got %d elementos", len(body))
	}
}

func TestDomainsConDatos(t *testing.T) {
	eng := &mockEngine{
		domains: []detection.DomainStat{
			{Domain: "example.com", Alerts: 5},
		},
	}
	srv := newTestServer(&mockEnforcer{}, eng)
	rr := do(t, srv, http.MethodGet, "/domains")

	var body []map[string]any
	json.NewDecoder(rr.Body).Decode(&body)
	if len(body) != 1 || body[0]["domain"] != "example.com" {
		t.Errorf("domains: got %v", body)
	}
}

// ── /whitelist ────────────────────────────────────────────────────────────────

func TestWhitelistGetSinWhitelist(t *testing.T) {
	srv := newTestServer(&mockEnforcer{}, &mockEngine{})
	rr := do(t, srv, http.MethodGet, "/whitelist")
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("sin whitelist: got %d, want 503", rr.Code)
	}
}

func TestWhitelistGetConDatos(t *testing.T) {
	srv := newFullTestServer(&mockEnforcer{}, &mockEngine{}, func(d *api.Dependencies) {
		d.Whitelist = &mockWhitelist{
			ips:      []string{"10.0.0.0/8"},
			accounts: []string{"admin@example.com"},
		}
	})
	rr := do(t, srv, http.MethodGet, "/whitelist")
	if rr.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", rr.Code)
	}
	var body map[string]any
	json.NewDecoder(rr.Body).Decode(&body)
	ips := body["ips"].([]any)
	if len(ips) != 1 {
		t.Errorf("ips: got %d, want 1", len(ips))
	}
}

func TestWhitelistAddIP(t *testing.T) {
	wl := &mockWhitelist{}
	srv := newFullTestServer(&mockEnforcer{}, &mockEngine{}, func(d *api.Dependencies) {
		d.Whitelist = wl
	})
	rr := do(t, srv, http.MethodPost, "/whitelist/1.2.3.4")
	if rr.Code != http.StatusOK {
		t.Fatalf("add IP: got %d, want 200", rr.Code)
	}
	var body map[string]string
	json.NewDecoder(rr.Body).Decode(&body)
	if body["added_ip"] != "1.2.3.4" {
		t.Errorf("added_ip: got %q", body["added_ip"])
	}
}

func TestWhitelistAddAccount(t *testing.T) {
	wl := &mockWhitelist{}
	srv := newFullTestServer(&mockEnforcer{}, &mockEngine{}, func(d *api.Dependencies) {
		d.Whitelist = wl
	})
	rr := do(t, srv, http.MethodPost, "/whitelist/user@example.com")
	if rr.Code != http.StatusOK {
		t.Fatalf("add account: got %d, want 200", rr.Code)
	}
	var body map[string]string
	json.NewDecoder(rr.Body).Decode(&body)
	if body["added_account"] != "user@example.com" {
		t.Errorf("added_account: got %q", body["added_account"])
	}
}

func TestWhitelistRemoveIP(t *testing.T) {
	wl := &mockWhitelist{ips: []string{"5.5.5.5/32"}}
	srv := newFullTestServer(&mockEnforcer{}, &mockEngine{}, func(d *api.Dependencies) {
		d.Whitelist = wl
	})
	rr := do(t, srv, http.MethodDelete, "/whitelist/5.5.5.5")
	if rr.Code != http.StatusOK {
		t.Fatalf("remove IP: got %d, want 200", rr.Code)
	}
	var body map[string]string
	json.NewDecoder(rr.Body).Decode(&body)
	if body["removed_ip"] != "5.5.5.5" {
		t.Errorf("removed_ip: got %q", body["removed_ip"])
	}
}

func TestWhitelistRemoveAccount(t *testing.T) {
	wl := &mockWhitelist{accounts: []string{"user@example.com"}}
	srv := newFullTestServer(&mockEnforcer{}, &mockEngine{}, func(d *api.Dependencies) {
		d.Whitelist = wl
	})
	rr := do(t, srv, http.MethodDelete, "/whitelist/user@example.com")
	if rr.Code != http.StatusOK {
		t.Fatalf("remove account: got %d, want 200", rr.Code)
	}
	var body map[string]string
	json.NewDecoder(rr.Body).Decode(&body)
	if body["removed_account"] != "user@example.com" {
		t.Errorf("removed_account: got %q", body["removed_account"])
	}
}

func TestWhitelistAddSinWhitelist(t *testing.T) {
	srv := newTestServer(&mockEnforcer{}, &mockEngine{})
	rr := do(t, srv, http.MethodPost, "/whitelist/1.2.3.4")
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("sin whitelist: got %d, want 503", rr.Code)
	}
}

func TestWhitelistRemoveSinWhitelist(t *testing.T) {
	srv := newTestServer(&mockEnforcer{}, &mockEngine{})
	rr := do(t, srv, http.MethodDelete, "/whitelist/1.2.3.4")
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("sin whitelist: got %d, want 503", rr.Code)
	}
}
