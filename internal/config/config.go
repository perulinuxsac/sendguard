package config

import (
	"errors"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	ServerID     string         `yaml:"server_id"`
	ClientName   string         `yaml:"client_name"`
	Zimbra       ZimbraConf     `yaml:"zimbra"`
	Rules        Rules          `yaml:"rules"`
	GeoIP        GeoIPConf      `yaml:"geoip"`
	AbuseIPDB    AbuseIPDBConf  `yaml:"abuseipdb"`
	AuditLog     AuditLogConf   `yaml:"audit_log"`
	LocalDB      LocalDBConf    `yaml:"local_db"`
	Controller   ControllerConf `yaml:"controller"`
	Firewall     FirewallConf   `yaml:"firewall"`
	Whitelist    Whitelist      `yaml:"whitelist"`
	Notification NotifyConf     `yaml:"notification"`
	API          APIConf        `yaml:"api"`
}

// ControllerConf configura la sincronización con el Controller central (Fase 3).
type ControllerConf struct {
	URL          string `yaml:"url"`           // vacío = modo standalone (sin envío)
	APIKey       string `yaml:"api_key"`       // Bearer token para autenticar con el Controller
	SyncInterval int    `yaml:"sync_interval"` // segundos entre intentos de sync (default: 30)
	BatchSize    int    `yaml:"batch_size"`    // alertas por lote (default: 100)
}

// APIConf configura el servidor HTTP de observabilidad del agente.
type APIConf struct {
	Listen string `yaml:"listen"`  // ej: "127.0.0.1:9099" — vacío deshabilita la API
	APIKey string `yaml:"api_key"` // si no está vacío, los endpoints de escritura requieren X-Api-Key
}

type ZimbraConf struct {
	Logs        LogPaths `yaml:"logs"`
	Workers     int      `yaml:"workers"`
	PostfixSbin string   `yaml:"postfix_sbin"` // dir de binarios de Postfix de Zimbra
	PostfixConf string   `yaml:"postfix_conf"` // dir de configuración de Postfix de Zimbra
}

type LogPaths struct {
	Main    string `yaml:"main"`    // /var/log/mail.log — fuente principal (obligatoria)
	Mailbox string `yaml:"mailbox"` // /opt/zimbra/log/mailbox.log — IMAP/POP3/SOAP (opcional)
}

type Rules struct {
	AuthFailed struct {
		MaxFailures int `yaml:"max_auth_failures"` // bloquear IP tras N fallos
		ScanTime    int `yaml:"scan_time"`          // ventana en segundos
	} `yaml:"auth_failed"`

	NumberMessages struct {
		MaxMessages int `yaml:"max_messages"` // máximo de mensajes en ventana
		ScanTime    int `yaml:"scan_time"`    // ventana en segundos
	} `yaml:"number_messages"`

	SaslConnections struct {
		Max      int `yaml:"max_sasl_connections"` // conexiones SASL simultáneas
		ScanTime int `yaml:"scan_time"`
	} `yaml:"sasl_connections"`

	ImpossibleTraveler struct {
		WindowMinutes int `yaml:"window_minutes"` // tiempo mínimo de viaje imposible
	} `yaml:"impossible_traveler"`

	QueueMonitor struct {
		Threshold int `yaml:"queue_threshold"` // deferrals por dominio destino para alertar
		ScanTime  int `yaml:"scan_time"`        // ventana en segundos
	} `yaml:"queue_monitor"`

	DomainDiscovery struct {
		MaxDomains int `yaml:"max_domains"` // dominios únicos atacados desde una IP para bloquear
		ScanTime   int `yaml:"scan_time"`   // ventana en segundos
	} `yaml:"domain_discovery"`

	BounceRate struct {
		MaxBounces int `yaml:"max_bounces"` // rebotes por cuenta para suspender
		ScanTime   int `yaml:"scan_time"`   // ventana en segundos
	} `yaml:"bounce_rate"`
}

type GeoIPConf struct {
	APIURL           string   `yaml:"api_url"`
	Token            string   `yaml:"token"`     // opcional: Bearer token para ipinfo.io (aumenta límite a 50k→ilimitado)
	CacheTTL         int      `yaml:"cache_ttl"` // horas
	AllowedCountries []string `yaml:"allowed_countries"`
}

// AbuseIPDBConf configura la integración con AbuseIPDB para enriquecer alertas.
type AbuseIPDBConf struct {
	APIKey   string `yaml:"api_key"`   // clave de API (vacío deshabilita la integración)
	CacheTTL int    `yaml:"cache_ttl"` // TTL de la caché en horas (default: 24)
}

// AuditLogConf configura el archivo de auditoría NDJSON.
type AuditLogConf struct {
	Path string `yaml:"path"` // ruta del archivo (vacío deshabilita el audit log)
}

// LocalDBConf configura la base de datos SQLite local del agente.
type LocalDBConf struct {
	Path      string `yaml:"path"`        // ruta del archivo SQLite (vacío deshabilita la persistencia local)
	MaxSizeMB int    `yaml:"max_size_mb"` // tamaño máximo antes de rotar (informativo; no se aplica automáticamente)
}

type FirewallConf struct {
	Backend    string `yaml:"backend"`     // "firewalld" (único soportado por ahora)
	BanSeconds int    `yaml:"ban_seconds"` // duración del bloqueo (0 = permanente)
}

type Whitelist struct {
	Accounts []string `yaml:"accounts"` // cuentas exentas de detección
	IPs      []string `yaml:"ips"`      // IPs exentas (red de oficina, etc.)
}

// NotifyConf agrupa los canales de notificación disponibles.
// Cada canal es opcional; se activa solo si sus campos obligatorios están presentes.
type NotifyConf struct {
	Telegram TelegramConf `yaml:"telegram"`
	Webhook  WebhookConf  `yaml:"webhook"`
}

type TelegramConf struct {
	Token  string `yaml:"token"`   // token del bot (requerido para activar el canal)
	ChatID string `yaml:"chat_id"` // ID del chat/grupo/canal destino
}

// WebhookConf configura el notificador HTTP genérico (Slack, Teams, n8n, etc.).
type WebhookConf struct {
	URL     string `yaml:"url"`     // endpoint destino (requerido para activar el canal)
	Timeout int    `yaml:"timeout"` // timeout en segundos (default: 10)
}

// Default retorna una configuración con valores seguros por defecto.
func Default() *Config {
	cfg := &Config{}
	cfg.Zimbra.Logs.Main = "/var/log/mail.log"
	cfg.Zimbra.Logs.Mailbox = "/opt/zimbra/log/mailbox.log"
	cfg.Zimbra.Workers = 4
	cfg.Zimbra.PostfixSbin = "/opt/zimbra/common/sbin"
	cfg.Zimbra.PostfixConf = "/opt/zimbra/common/conf"

	cfg.Rules.AuthFailed.MaxFailures = 5
	cfg.Rules.AuthFailed.ScanTime = 300

	cfg.Rules.NumberMessages.MaxMessages = 300
	cfg.Rules.NumberMessages.ScanTime = 3600

	cfg.Rules.SaslConnections.Max = 20
	cfg.Rules.SaslConnections.ScanTime = 300

	cfg.Rules.ImpossibleTraveler.WindowMinutes = 30

	cfg.Rules.QueueMonitor.Threshold = 2500
	cfg.Rules.QueueMonitor.ScanTime = 3600

	cfg.Rules.DomainDiscovery.MaxDomains = 10
	cfg.Rules.DomainDiscovery.ScanTime = 600

	cfg.Rules.BounceRate.MaxBounces = 50
	cfg.Rules.BounceRate.ScanTime = 300

	cfg.GeoIP.APIURL = "https://ipinfo.io"
	cfg.GeoIP.CacheTTL = 24

	cfg.Firewall.Backend = "firewalld"
	cfg.Firewall.BanSeconds = 3600

	cfg.API.Listen = "127.0.0.1:9099"
	cfg.AuditLog.Path = "/var/log/sendguard-audit.log"

	cfg.LocalDB.Path = "/var/lib/sendguard/sendguard.db"
	cfg.LocalDB.MaxSizeMB = 100

	cfg.Controller.SyncInterval = 30
	cfg.Controller.BatchSize = 100

	return cfg
}

// Load lee y parsea el archivo YAML de configuración.
// Los campos no definidos mantienen los valores por defecto.
func Load(path string) (*Config, error) {
	cfg := Default()

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cfg, nil // sin config, usar defaults
		}
		return nil, err
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	if cfg.Zimbra.Logs.Main == "" {
		return nil, errors.New("zimbra.logs.main es obligatorio")
	}

	return cfg, nil
}
