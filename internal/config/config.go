package config

import (
	"errors"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	ServerID     string          `yaml:"server_id"`
	ClientName   string          `yaml:"client_name"`
	Zimbra       ZimbraConf      `yaml:"zimbra"`
	Rules        Rules           `yaml:"rules"`
	GeoIP        GeoIPConf       `yaml:"geoip"`
	AbuseIPDB    AbuseIPDBConf   `yaml:"abuseipdb"`
	AuditLog     AuditLogConf    `yaml:"audit_log"`
	LocalDB      LocalDBConf     `yaml:"local_db"`
	Controller   ControllerConf  `yaml:"controller"`
	Firewall     FirewallConf    `yaml:"firewall"`
	Whitelist    Whitelist       `yaml:"whitelist"`
	// ProxyCIDRs: rangos de proxies cloud legítimos (Microsoft, Google, Apple…).
	// Los eventos de estas IPs no activan módulos IP-céntricos (auth_failed, rcpt_flood)
	// pero sí los de cuenta (sasl_connections, impossible_traveler).
	ProxyCIDRs   []string          `yaml:"proxy_cidrs"`
	Notification NotifyConf        `yaml:"notification"`
	API          APIConf           `yaml:"api"`
	DailyReport  DailyReportConf   `yaml:"daily_report"`
	PolicyDaemon PolicyDaemonConf  `yaml:"policy_daemon"`
}

// DailyReportConf configura el envío del resumen diario por email.
type DailyReportConf struct {
	Hour int `yaml:"hour"` // hora UTC en que se envía (0-23, default 8)
}

// PolicyDaemonConf configura el daemon de políticas Postfix.
type PolicyDaemonConf struct {
	Listen string `yaml:"listen"` // ej: "127.0.0.1:9100" — vacío deshabilita el daemon
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
	ZmprovBin   string   `yaml:"zmprov_bin"`   // ruta completa a zmprov (default: /opt/zimbra/bin/zmprov)
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
		Max          int `yaml:"max_sasl_connections"` // conexiones totales por cuenta en ventana
		MaxUniqueIPs int `yaml:"max_unique_ips"`        // IPs distintas por cuenta (0 = deshabilitado)
		ScanTime     int `yaml:"scan_time"`
	} `yaml:"sasl_connections"`

	DistBrute struct {
		MaxIPs   int `yaml:"max_ips"`   // IPs distintas fallando por cuenta para notificar
		ScanTime int `yaml:"scan_time"` // ventana en segundos
	} `yaml:"dist_brute_force"`

	ImpossibleTraveler struct {
		WindowMinutes int      `yaml:"window_minutes"` // tiempo mínimo de viaje imposible
		TrustedCIDRs  []string `yaml:"trusted_cidrs"`  // rangos CIDR de proxies conocidos a ignorar
		TrustedOrgs   []string `yaml:"trusted_orgs"`   // nombres de org/ASN de proxies conocidos (via ipinfo.io)
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

	RcptFlood struct {
		MaxRecipients int `yaml:"max_recipients"` // destinatarios por IP en ventana para bloquear
		ScanTime      int `yaml:"scan_time"`       // ventana en segundos
	} `yaml:"rcpt_flood"`

	PasswordSpray struct {
		MaxAccounts int `yaml:"max_accounts"` // cuentas distintas desde la misma IP para bloquearla
		ScanTime    int `yaml:"scan_time"`    // ventana en segundos
	} `yaml:"password_spray"`

	AccountTakeover struct {
		MinFailures  int `yaml:"min_failures"`   // fallos mínimos antes de vigilar la cuenta
		CorrelWindow int `yaml:"correl_window"`  // ventana de correlación en segundos
	} `yaml:"account_takeover"`
}

type GeoIPConf struct {
	// DBPath: ruta al archivo GeoLite2-Country.mmdb (recomendado para producción).
	// Si está configurado, se usa la DB local (sin red, sin rate-limit).
	// Si está vacío, se cae al HTTP API definido en APIURL.
	DBPath           string   `yaml:"db_path"`
	APIURL           string   `yaml:"api_url"`
	Token            string   `yaml:"token"`     // opcional: Bearer token para ipinfo.io
	CacheTTL         int      `yaml:"cache_ttl"` // horas (aplica solo al modo HTTP API)
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
	Telegram        TelegramConf    `yaml:"telegram"`
	Webhook         WebhookConf     `yaml:"webhook"`
	Email           EmailConf       `yaml:"email"`
	CooldownSeconds int             `yaml:"cooldown_seconds"` // cooldown por IP/cuenta (0 = deshabilitado)
	MaxPerMinute    int             `yaml:"max_per_minute"`   // límite global por minuto (0 = deshabilitado)
	// OnActions filtra las notificaciones push (Telegram/email/webhook) por acción.
	// Si está vacío se notifica todo. Valores: block_ip | suspend_account | rate_limit | purge_queue | notify_only
	OnActions       []string        `yaml:"on_actions"`
}

// EmailConf configura el notificador de email via sendmail local de Zimbra.
// No requiere credenciales SMTP — usa /opt/zimbra/common/sbin/sendmail directamente.
type EmailConf struct {
	From        string   `yaml:"from"`         // dirección remitente (requerido para activar el canal)
	To          []string `yaml:"to"`           // destinatarios (al menos uno requerido)
	SendmailBin string   `yaml:"sendmail_bin"` // default: /opt/zimbra/common/sbin/sendmail
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
	cfg.Zimbra.ZmprovBin = "/opt/zimbra/bin/zmprov"
	cfg.Zimbra.PostfixSbin = "/opt/zimbra/common/sbin"
	cfg.Zimbra.PostfixConf = "/opt/zimbra/common/conf"

	cfg.Rules.AuthFailed.MaxFailures = 5
	cfg.Rules.AuthFailed.ScanTime = 300

	cfg.Rules.NumberMessages.MaxMessages = 300
	cfg.Rules.NumberMessages.ScanTime = 3600

	cfg.Rules.SaslConnections.Max = 20
	cfg.Rules.SaslConnections.MaxUniqueIPs = 5
	cfg.Rules.SaslConnections.ScanTime = 300

	cfg.Rules.DistBrute.MaxIPs = 5
	cfg.Rules.DistBrute.ScanTime = 300

	cfg.Rules.ImpossibleTraveler.WindowMinutes = 30

	cfg.Rules.QueueMonitor.Threshold = 2500
	cfg.Rules.QueueMonitor.ScanTime = 3600

	cfg.Rules.DomainDiscovery.MaxDomains = 10
	cfg.Rules.DomainDiscovery.ScanTime = 600

	cfg.Rules.BounceRate.MaxBounces = 50
	cfg.Rules.BounceRate.ScanTime = 300

	cfg.Rules.RcptFlood.MaxRecipients = 50
	cfg.Rules.RcptFlood.ScanTime = 300

	cfg.Rules.PasswordSpray.MaxAccounts = 10
	cfg.Rules.PasswordSpray.ScanTime = 300

	cfg.Rules.AccountTakeover.MinFailures = 5
	cfg.Rules.AccountTakeover.CorrelWindow = 600 // 10 minutos

	cfg.DailyReport.Hour = 8

	cfg.Notification.CooldownSeconds = 300 // 5 min entre notificaciones del mismo IP/cuenta
	cfg.Notification.MaxPerMinute = 10    // máximo 10 notificaciones distintas por minuto

	cfg.GeoIP.APIURL = "https://ipinfo.io"
	cfg.GeoIP.CacheTTL = 24

	// Proxies cloud conocidos: IPs de estos rangos no activan auth_failed/rcpt_flood.
	cfg.ProxyCIDRs = []string{
		"52.96.0.0/12",    // Microsoft Office 365 / Outlook Mobile
		"52.112.0.0/14",   // Microsoft Teams / Exchange Online
		"104.47.0.0/17",   // Microsoft Exchange Online Protection
		"40.92.0.0/15",    // Microsoft Exchange
		"40.107.0.0/16",   // Microsoft Exchange
		"66.102.0.0/20",   // Google Mail
		"209.85.128.0/17", // Google SMTP
		"17.0.0.0/8",      // Apple (iCloud Mail)
	}

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
