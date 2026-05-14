package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultValues(t *testing.T) {
	cfg := Default()

	checks := []struct {
		name string
		got  any
		want any
	}{
		{"Zimbra.Logs.Main", cfg.Zimbra.Logs.Main, "/var/log/mail.log"},
		{"Zimbra.Workers", cfg.Zimbra.Workers, 4},
		{"Rules.AuthFailed.MaxFailures", cfg.Rules.AuthFailed.MaxFailures, 5},
		{"Rules.AuthFailed.ScanTime", cfg.Rules.AuthFailed.ScanTime, 300},
		{"Rules.NumberMessages.MaxMessages", cfg.Rules.NumberMessages.MaxMessages, 300},
		{"Rules.NumberMessages.ScanTime", cfg.Rules.NumberMessages.ScanTime, 3600},
		{"Rules.SaslConnections.Max", cfg.Rules.SaslConnections.Max, 20},
		{"Rules.ImpossibleTraveler.WindowMinutes", cfg.Rules.ImpossibleTraveler.WindowMinutes, 30},
		{"Rules.QueueMonitor.Threshold", cfg.Rules.QueueMonitor.Threshold, 2500},
		{"Rules.DomainDiscovery.MaxDomains", cfg.Rules.DomainDiscovery.MaxDomains, 10},
		{"Rules.BounceRate.MaxBounces", cfg.Rules.BounceRate.MaxBounces, 50},
		{"Firewall.Backend", cfg.Firewall.Backend, "firewalld"},
		{"Firewall.BanSeconds", cfg.Firewall.BanSeconds, 3600},
		{"GeoIP.CacheTTL", cfg.GeoIP.CacheTTL, 24},
		{"API.Listen", cfg.API.Listen, "127.0.0.1:9099"},
	}

	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("Default.%s: got %v, want %v", c.name, c.got, c.want)
		}
	}

	if cfg.LocalDB.Path == "" {
		t.Error("LocalDB.Path no debe estar vacío en default")
	}
	if cfg.AuditLog.Path == "" {
		t.Error("AuditLog.Path no debe estar vacío en default")
	}
}

func TestLoadArchivoNoExiste(t *testing.T) {
	cfg, err := Load("/no/existe/config.yaml")
	if err != nil {
		t.Fatalf("archivo inexistente debe retornar defaults sin error, got: %v", err)
	}
	if cfg.Zimbra.Logs.Main != "/var/log/mail.log" {
		t.Errorf("default main log: got %q", cfg.Zimbra.Logs.Main)
	}
	if cfg.Firewall.BanSeconds != 3600 {
		t.Errorf("default BanSeconds: got %d", cfg.Firewall.BanSeconds)
	}
}

func TestLoadMainVacioError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.yaml")
	os.WriteFile(path, []byte("zimbra:\n  logs:\n    main: \"\"\n"), 0644)

	_, err := Load(path)
	if err == nil {
		t.Error("zimbra.logs.main vacío debe retornar error")
	}
}

func TestLoadOverrideDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.yaml")

	yaml := `
server_id: "srv-test"
client_name: "Test SA"
zimbra:
  logs:
    main: "/custom/mail.log"
rules:
  auth_failed:
    max_auth_failures: 10
    scan_time: 600
  bounce_rate:
    max_bounces: 25
    scan_time: 120
firewall:
  ban_seconds: 7200
`
	os.WriteFile(path, []byte(yaml), 0644)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.ServerID != "srv-test" {
		t.Errorf("ServerID: got %q", cfg.ServerID)
	}
	if cfg.Zimbra.Logs.Main != "/custom/mail.log" {
		t.Errorf("Main: got %q", cfg.Zimbra.Logs.Main)
	}
	if cfg.Rules.AuthFailed.MaxFailures != 10 {
		t.Errorf("MaxFailures: got %d, want 10", cfg.Rules.AuthFailed.MaxFailures)
	}
	if cfg.Rules.AuthFailed.ScanTime != 600 {
		t.Errorf("ScanTime: got %d, want 600", cfg.Rules.AuthFailed.ScanTime)
	}
	if cfg.Firewall.BanSeconds != 7200 {
		t.Errorf("BanSeconds: got %d, want 7200", cfg.Firewall.BanSeconds)
	}
	// Campos no definidos en YAML → default preservado
	if cfg.Rules.NumberMessages.MaxMessages != 300 {
		t.Errorf("MaxMessages (default): got %d, want 300", cfg.Rules.NumberMessages.MaxMessages)
	}
}

func TestLoadArchivoInvalido(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	os.WriteFile(path, []byte("{ invalid: [unclosed"), 0644)

	_, err := Load(path)
	if err == nil {
		t.Error("YAML inválido debe retornar error")
	}
}

func TestLoadNotificacionTelegram(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.yaml")

	yaml := `
zimbra:
  logs:
    main: "/var/log/mail.log"
notification:
  telegram:
    token: "bot123:ABC"
    chat_id: "-100456789"
  webhook:
    url: "https://hooks.example.com/notify"
    timeout: 30
`
	os.WriteFile(path, []byte(yaml), 0644)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Notification.Telegram.Token != "bot123:ABC" {
		t.Errorf("Telegram.Token: got %q", cfg.Notification.Telegram.Token)
	}
	if cfg.Notification.Webhook.URL != "https://hooks.example.com/notify" {
		t.Errorf("Webhook.URL: got %q", cfg.Notification.Webhook.URL)
	}
	if cfg.Notification.Webhook.Timeout != 30 {
		t.Errorf("Webhook.Timeout: got %d, want 30", cfg.Notification.Webhook.Timeout)
	}
}
