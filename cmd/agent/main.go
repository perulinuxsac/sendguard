package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/perulinux/sendguard/internal/abuseipdb"
	"github.com/perulinux/sendguard/internal/api"
	"github.com/perulinux/sendguard/internal/audit"
	"github.com/perulinux/sendguard/internal/config"
	"github.com/perulinux/sendguard/internal/detection"
	"github.com/perulinux/sendguard/internal/forwarder"
	"github.com/perulinux/sendguard/internal/version"
	"github.com/perulinux/sendguard/internal/detection/authfailed"
	"github.com/perulinux/sendguard/internal/detection/bouncerate"
	"github.com/perulinux/sendguard/internal/detection/domaindiscovery"
	"github.com/perulinux/sendguard/internal/detection/impossibletraveler"
	"github.com/perulinux/sendguard/internal/detection/numbermessages"
	"github.com/perulinux/sendguard/internal/detection/queuemonitor"
	"github.com/perulinux/sendguard/internal/detection/saslconnections"
	"github.com/perulinux/sendguard/internal/enforcement"
	"github.com/perulinux/sendguard/internal/event"
	"github.com/perulinux/sendguard/internal/geoip"
	"github.com/perulinux/sendguard/internal/notify"
	"github.com/perulinux/sendguard/internal/notify/telegram"
	"github.com/perulinux/sendguard/internal/notify/webhook"
	"github.com/perulinux/sendguard/internal/parser"
	"github.com/perulinux/sendguard/internal/store"
	"github.com/perulinux/sendguard/internal/watcher"
)

func main() {
	configPath := flag.String("config", "/etc/sendguard/agent.yaml", "ruta al archivo de configuración")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.Error("no se pudo cargar la configuración", "error", err, "path", *configPath)
		os.Exit(1)
	}

	slog.Info("sendguard agent iniciando",
		"version", version.Version,
		"commit", version.Commit,
		"server_id", cfg.ServerID,
		"client", cfg.ClientName,
		"log", cfg.Zimbra.Logs.Main,
	)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// --- Pipeline de eventos ---
	// watcher → eventCh → engine (módulos de detección) → alertCh → enforcer

	eventCh := make(chan event.Event, 10_000)
	alertCh := make(chan detection.Alert, 1_000)

	// Whitelist compartida entre engine y enforcer
	wl := detection.NewWhitelist(cfg.Whitelist.IPs, cfg.Whitelist.Accounts)

	// Resolver GeoIP (compartido entre módulos que lo necesiten)
	geoResolver := geoip.New(
		cfg.GeoIP.APIURL,
		cfg.GeoIP.Token,
		time.Duration(cfg.GeoIP.CacheTTL)*time.Hour,
	)

	// Módulos de detección activos
	authFailed := authfailed.New(authfailed.Config{
		MaxFailures: cfg.Rules.AuthFailed.MaxFailures,
		ScanTime:    time.Duration(cfg.Rules.AuthFailed.ScanTime) * time.Second,
	})

	numberMessages := numbermessages.New(numbermessages.Config{
		MaxMessages: cfg.Rules.NumberMessages.MaxMessages,
		ScanTime:    time.Duration(cfg.Rules.NumberMessages.ScanTime) * time.Second,
	})

	saslConns := saslconnections.New(saslconnections.Config{
		Max:      cfg.Rules.SaslConnections.Max,
		ScanTime: time.Duration(cfg.Rules.SaslConnections.ScanTime) * time.Second,
	})

	impossTravel := impossibletraveler.New(impossibletraveler.Config{
		WindowMinutes: cfg.Rules.ImpossibleTraveler.WindowMinutes,
	}, geoResolver)

	queueMon := queuemonitor.New(queuemonitor.Config{
		Threshold: cfg.Rules.QueueMonitor.Threshold,
		ScanTime:  time.Duration(cfg.Rules.QueueMonitor.ScanTime) * time.Second,
	})

	domainDisc := domaindiscovery.New(domaindiscovery.Config{
		MaxDomains: cfg.Rules.DomainDiscovery.MaxDomains,
		ScanTime:   time.Duration(cfg.Rules.DomainDiscovery.ScanTime) * time.Second,
	})

	bounceRate := bouncerate.New(bouncerate.Config{
		MaxBounces: cfg.Rules.BounceRate.MaxBounces,
		ScanTime:   time.Duration(cfg.Rules.BounceRate.ScanTime) * time.Second,
	})

	// Engine: distribuye eventos a los módulos
	engine := detection.NewEngine(alertCh, wl, authFailed, numberMessages, saslConns, impossTravel, queueMon, domainDisc, bounceRate)

	// Notifier: construir canales activos según config
	var notifiers []notify.Notifier
	tgCfg := cfg.Notification.Telegram
	if tgCfg.Token != "" && tgCfg.ChatID != "" {
		notifiers = append(notifiers, telegram.New(telegram.Config{
			Token:  tgCfg.Token,
			ChatID: tgCfg.ChatID,
		}))
		slog.Info("notificaciones telegram activadas", "chat_id", tgCfg.ChatID)
	}
	whCfg := cfg.Notification.Webhook
	if whCfg.URL != "" {
		notifiers = append(notifiers, webhook.New(webhook.Config{
			URL:     whCfg.URL,
			Timeout: whCfg.Timeout,
		}))
		slog.Info("notificaciones webhook activadas", "url", whCfg.URL)
	}

	// Cliente AbuseIPDB (opcional)
	var abuseClient *abuseipdb.Client
	if cfg.AbuseIPDB.APIKey != "" {
		cacheTTL := time.Duration(cfg.AbuseIPDB.CacheTTL) * time.Hour
		if cacheTTL == 0 {
			cacheTTL = 24 * time.Hour
		}
		abuseClient = abuseipdb.New(abuseipdb.Config{
			APIKey:   cfg.AbuseIPDB.APIKey,
			CacheTTL: cacheTTL,
		})
		slog.Info("abuseipdb activado")
	}

	// Audit log (opcional)
	var auditLog *audit.Logger
	if cfg.AuditLog.Path != "" {
		var err error
		auditLog, err = audit.New(cfg.AuditLog.Path)
		if err != nil {
			slog.Error("no se pudo abrir audit log", "error", err, "path", cfg.AuditLog.Path)
			os.Exit(1)
		}
		slog.Info("audit log activado", "path", cfg.AuditLog.Path)
	}

	// Store SQLite local (persistencia de bans y StoreAndForward)
	var localStore *store.Store
	if cfg.LocalDB.Path != "" {
		var err error
		localStore, err = store.Open(cfg.LocalDB.Path)
		if err != nil {
			slog.Error("no se pudo abrir base de datos local", "error", err, "path", cfg.LocalDB.Path)
			os.Exit(1)
		}
		defer localStore.Close()

		// Prune periódico: eliminar bans expirados cada hora para mantener la DB compacta.
		go func() {
			ticker := time.NewTicker(time.Hour)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if n, err := localStore.PruneExpiredBans(); err != nil {
						slog.Warn("store: error al podar bans expirados", "error", err)
					} else if n > 0 {
						slog.Info("store: bans expirados eliminados", "count", n)
					}
				}
			}
		}()
	}

	// Forwarder: StoreAndForward hacia el Controller central (Fase 3)
	fwd := forwarder.New(forwarder.Config{
		Store:         localStore,
		ControllerURL: cfg.Controller.URL,
		APIKey:        cfg.Controller.APIKey,
		SyncInterval:  time.Duration(cfg.Controller.SyncInterval) * time.Second,
		BatchSize:     cfg.Controller.BatchSize,
	})
	go fwd.Run(ctx)

	// Enforcer: ejecuta las acciones de contención
	enforcer := enforcement.New(enforcement.Config{
		FirewallBackend: cfg.Firewall.Backend,
		BanSeconds:      cfg.Firewall.BanSeconds,
		PostfixSbin:     cfg.Zimbra.PostfixSbin,
		PostfixConf:     cfg.Zimbra.PostfixConf,
		Notifier:        notify.NewMulti(notifiers...),
		AbuseIPDB:       abuseClient,
		AuditLog:        auditLog,
		Store:           localStore,
		Forwarder:       fwd,
	})

	// Restaurar bans activos de firewalld (resiliencia al reinicio)
	enforcer.LoadExistingBans(ctx)

	// Watchers: leen los logs y parsean eventos hacia el mismo canal
	p := parser.New()

	// mail.log — SMTP/SASL (obligatorio)
	go watcher.New(cfg.Zimbra.Logs.Main, p.ParseLine, "", eventCh).Run(ctx)

	// mailbox.log — IMAP/POP3/SOAP (opcional; si está vacío en config, no se inicia)
	if cfg.Zimbra.Logs.Mailbox != "" {
		go watcher.New(cfg.Zimbra.Logs.Mailbox, p.ParseMailboxLine, cfg.ServerID, eventCh).Run(ctx)
		slog.Info("watcher mailbox iniciado", "path", cfg.Zimbra.Logs.Mailbox)
	}

	go engine.Run(ctx, eventCh)
	go enforcer.Run(ctx, alertCh)

	// API HTTP de observabilidad (opcional; deshabilitada si Listen está vacío)
	if cfg.API.Listen != "" {
		apiDeps := api.Dependencies{
			Enforcer:    enforcer,
			Engine:      api.AdaptEngine(engine),
			Whitelist:   wl,
			GeoIP:       geoResolver,
			PostfixSbin: cfg.Zimbra.PostfixSbin,
			PostfixConf: cfg.Zimbra.PostfixConf,
			StartTime:   time.Now(),
			APIKey:      cfg.API.APIKey,
		}
		// Evitar el nil interface trap: solo asignar si el cliente existe.
		if abuseClient != nil {
			apiDeps.AbuseIPDB = abuseClient
		}
		go api.New(cfg.API.Listen, apiDeps).Run(ctx)
	}

	// Esperar señal de shutdown
	<-ctx.Done()
	slog.Info("sendguard agent detenido")
}
