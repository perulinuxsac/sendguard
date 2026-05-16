// Package detection orquesta los módulos de detección.
// El Engine recibe eventos del watcher y los distribuye a cada módulo.
// Las alertas resultantes se envían al Enforcer para ejecutar las acciones.
package detection

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/perulinux/sendguard/internal/event"
)

// Whitelist contiene IPs/CIDRs y cuentas exentas de detección.
// Es thread-safe: puede modificarse en caliente desde la API HTTP.
type Whitelist struct {
	mu       sync.RWMutex
	nets     []*net.IPNet
	accounts map[string]struct{}
}

// NewWhitelist parsea las listas de IPs (individuales o CIDR) y cuentas.
// Las entradas inválidas se loguean y se ignoran.
func NewWhitelist(ips []string, accounts []string) *Whitelist {
	wl := &Whitelist{
		accounts: make(map[string]struct{}, len(accounts)),
	}
	for _, raw := range ips {
		if !strings.ContainsRune(raw, '/') {
			raw += "/32"
		}
		_, cidr, err := net.ParseCIDR(raw)
		if err != nil {
			slog.Warn("whitelist: IP/CIDR inválida, ignorando", "entry", raw)
			continue
		}
		wl.nets = append(wl.nets, cidr)
	}
	for _, a := range accounts {
		wl.accounts[a] = struct{}{}
	}
	return wl
}

func (wl *Whitelist) ContainsIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	wl.mu.RLock()
	defer wl.mu.RUnlock()
	for _, cidr := range wl.nets {
		if cidr.Contains(parsed) {
			return true
		}
	}
	return false
}

func (wl *Whitelist) ContainsAccount(account string) bool {
	wl.mu.RLock()
	defer wl.mu.RUnlock()
	_, ok := wl.accounts[account]
	return ok
}

// AddIP agrega una IP o CIDR a la whitelist en caliente.
func (wl *Whitelist) AddIP(ip string) error {
	raw := ip
	if !strings.ContainsRune(raw, '/') {
		raw += "/32"
	}
	_, cidr, err := net.ParseCIDR(raw)
	if err != nil {
		return fmt.Errorf("IP/CIDR inválida: %s", ip)
	}
	wl.mu.Lock()
	wl.nets = append(wl.nets, cidr)
	wl.mu.Unlock()
	return nil
}

// RemoveIP elimina una IP o CIDR exacta de la whitelist.
func (wl *Whitelist) RemoveIP(ip string) {
	raw := ip
	if !strings.ContainsRune(raw, '/') {
		raw += "/32"
	}
	_, target, err := net.ParseCIDR(raw)
	if err != nil {
		return
	}
	wl.mu.Lock()
	filtered := wl.nets[:0]
	for _, cidr := range wl.nets {
		if cidr.String() != target.String() {
			filtered = append(filtered, cidr)
		}
	}
	wl.nets = filtered
	wl.mu.Unlock()
}

// AddAccount agrega una cuenta a la whitelist en caliente.
func (wl *Whitelist) AddAccount(account string) {
	wl.mu.Lock()
	wl.accounts[account] = struct{}{}
	wl.mu.Unlock()
}

// RemoveAccount elimina una cuenta de la whitelist.
func (wl *Whitelist) RemoveAccount(account string) {
	wl.mu.Lock()
	delete(wl.accounts, account)
	wl.mu.Unlock()
}

// List retorna copias de los contenidos actuales de la whitelist.
func (wl *Whitelist) List() (ips []string, accounts []string) {
	wl.mu.RLock()
	defer wl.mu.RUnlock()
	for _, cidr := range wl.nets {
		ips = append(ips, cidr.String())
	}
	for a := range wl.accounts {
		accounts = append(accounts, a)
	}
	return
}

// DomainStat contiene la cantidad de alertas registradas para un dominio.
type DomainStat struct {
	Domain string `json:"domain"`
	Alerts int64  `json:"alerts"`
}

// ModuleStat contiene el total de alertas emitidas por un módulo de detección.
type ModuleStat struct {
	Module string `json:"module"`
	Alerts int64  `json:"alerts"`
}

// Engine distribuye eventos a los módulos de detección y envía alertas al canal.
type Engine struct {
	modules      []Module
	whitelist    *Whitelist
	alertCh      chan<- Alert
	EventsTotal  atomic.Int64 // total de eventos procesados
	AlertsTotal  atomic.Int64 // total de alertas emitidas
	domainMu     sync.RWMutex
	domainAlerts map[string]int64 // dominio → alertas acumuladas (protected by domainMu)
	moduleAlerts map[string]int64 // módulo → alertas emitidas (protected by domainMu)
	proxyCIDRs   []*net.IPNet     // rangos de proxies cloud: la IP se limpia antes de despachar
}

// NewEngine crea un Engine con los módulos y whitelist dados.
// alertCh debe tener suficiente buffer para no bloquear el loop de eventos.
func NewEngine(alertCh chan<- Alert, wl *Whitelist, modules ...Module) *Engine {
	return &Engine{
		modules:      modules,
		whitelist:    wl,
		alertCh:      alertCh,
		domainAlerts: make(map[string]int64),
		moduleAlerts: make(map[string]int64),
	}
}

// Run procesa eventos hasta que ctx sea cancelado.
// Debe ejecutarse en su propio goroutine.
func (e *Engine) Run(ctx context.Context, eventCh <-chan event.Event) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-eventCh:
			if !ok {
				return
			}
			e.dispatch(ev)
		}
	}
}

// SetProxyCIDRs registra rangos de proxies cloud (Microsoft, Google, Apple…).
// Los eventos cuya IP caiga en estos rangos tendrán la IP limpiada antes de ser
// despachados: los módulos IP-céntricos (auth_failed, rcpt_flood…) no cuentan la
// IP de proxy, pero los módulos de cuenta (sasl_connections, impossible_traveler…)
// siguen operando con normalidad.
// Llamar antes de Run().
func (e *Engine) SetProxyCIDRs(cidrs []string) {
	for _, raw := range cidrs {
		if !strings.ContainsRune(raw, '/') {
			raw += "/32"
		}
		_, cidr, err := net.ParseCIDR(raw)
		if err != nil {
			slog.Warn("engine: proxy CIDR inválida, ignorando", "entry", raw)
			continue
		}
		e.proxyCIDRs = append(e.proxyCIDRs, cidr)
	}
}

// isProxyIP comprueba si una IP pertenece a los rangos de proxy cloud configurados.
func (e *Engine) isProxyIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, cidr := range e.proxyCIDRs {
		if cidr.Contains(parsed) {
			return true
		}
	}
	return false
}

// dispatch envía un evento a todos los módulos, respetando la whitelist.
func (e *Engine) dispatch(ev event.Event) {
	e.EventsTotal.Add(1)
	if e.isWhitelisted(ev) {
		return
	}
	// Si la IP es de un proxy cloud conocido, limpiarla para que los módulos
	// IP-céntricos (auth_failed, rcpt_flood, etc.) no la bloqueen. Los módulos
	// que trabajan por cuenta (sasl_connections, impossible_traveler) no se ven
	// afectados porque usan ev.Account, no ev.IP.
	if ev.IP != "" && e.isProxyIP(ev.IP) {
		ev.IP = ""
	}
	for _, m := range e.modules {
		alerts := m.Handle(ev)
		for _, a := range alerts {
			e.AlertsTotal.Add(1)
			e.trackDomain(a)
			e.domainMu.Lock()
			e.moduleAlerts[m.Name()]++
			e.domainMu.Unlock()
			select {
			case e.alertCh <- a:
			default:
				slog.Warn("detection: canal de alertas lleno, alerta descartada",
					"module", m.Name(), "ip", a.IP, "account", a.Account)
			}
		}
	}
}

// trackDomain incrementa el contador de alertas del dominio de la alerta.
func (e *Engine) trackDomain(a Alert) {
	domain := a.Domain
	if domain == "" && a.Account != "" {
		if i := strings.LastIndex(a.Account, "@"); i >= 0 {
			domain = a.Account[i+1:]
		}
	}
	if domain == "" {
		return
	}
	e.domainMu.Lock()
	e.domainAlerts[domain]++
	e.domainMu.Unlock()
}

// ModuleStats retorna las alertas emitidas por cada módulo desde que arrancó el agente.
func (e *Engine) ModuleStats() []ModuleStat {
	e.domainMu.RLock()
	defer e.domainMu.RUnlock()
	result := make([]ModuleStat, 0, len(e.moduleAlerts))
	for mod, n := range e.moduleAlerts {
		result = append(result, ModuleStat{Module: mod, Alerts: n})
	}
	return result
}

// DomainStats retorna las alertas acumuladas por dominio desde que arrancó el agente.
func (e *Engine) DomainStats() []DomainStat {
	e.domainMu.RLock()
	defer e.domainMu.RUnlock()
	result := make([]DomainStat, 0, len(e.domainAlerts))
	for d, n := range e.domainAlerts {
		result = append(result, DomainStat{Domain: d, Alerts: n})
	}
	return result
}

func (e *Engine) isWhitelisted(ev event.Event) bool {
	if ev.IP != "" && e.whitelist.ContainsIP(ev.IP) {
		return true
	}
	if ev.Account != "" && e.whitelist.ContainsAccount(ev.Account) {
		return true
	}
	return false
}
