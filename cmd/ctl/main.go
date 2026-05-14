// sendguard-ctl es la herramienta de administración en línea de comandos para el agente SendGuard.
// Habla con la API HTTP del agente y permite consultar estado, bloquear IPs,
// inspeccionar la cola de correo y gestionar la whitelist en caliente.
//
// Uso:
//
//	sendguard-ctl [-addr http://127.0.0.1:9099] [-key <api-key>] <comando>
//
// Comandos:
//
//	status                        — muestra estado, IPs bloqueadas y contadores
//	block   <ip>                  — bloquea una IP manualmente vía la API
//	unblock <ip>                  — desbloquea una IP manualmente vía la API
//	health                        — verifica que el agente responde
//	urban   <ip>                  — inteligencia de IP (AbuseIPDB + GeoIP)
//	queue                         — muestra la cola de correo Postfix actual
//	domains                       — dominios con alertas desde que arrancó el agente
//	whitelist list                — muestra la whitelist actual
//	whitelist add    <ip|cuenta>  — agrega IP/CIDR o cuenta a la whitelist (en memoria)
//	whitelist remove <ip|cuenta>  — elimina IP/CIDR o cuenta de la whitelist (en memoria)
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"
)

func main() {
	addr := flag.String("addr", "http://127.0.0.1:9099", "dirección de la API del agente")
	key := flag.String("key", "", "API key (header X-Api-Key)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Uso: sendguard-ctl [-addr URL] [-key KEY] <comando>\n\n")
		fmt.Fprintf(os.Stderr, "Comandos:\n")
		fmt.Fprintf(os.Stderr, "  status                      muestra IPs bloqueadas y contadores\n")
		fmt.Fprintf(os.Stderr, "  block   <ip>                bloquea una IP manualmente\n")
		fmt.Fprintf(os.Stderr, "  unblock <ip>                desbloquea una IP manualmente\n")
		fmt.Fprintf(os.Stderr, "  health                      verifica que el agente está vivo\n")
		fmt.Fprintf(os.Stderr, "  urban   <ip>                inteligencia de IP (AbuseIPDB + GeoIP)\n")
		fmt.Fprintf(os.Stderr, "  queue                       cola de correo Postfix actual\n")
		fmt.Fprintf(os.Stderr, "  domains                     dominios con alertas acumuladas\n")
		fmt.Fprintf(os.Stderr, "  whitelist list              muestra la whitelist actual\n")
		fmt.Fprintf(os.Stderr, "  whitelist add    <val>      agrega IP/CIDR o cuenta (en memoria)\n")
		fmt.Fprintf(os.Stderr, "  whitelist remove <val>      elimina IP/CIDR o cuenta (en memoria)\n")
		fmt.Fprintf(os.Stderr, "\nOpciones:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(1)
	}

	cli := &apiClient{baseURL: *addr, apiKey: *key, http: &http.Client{Timeout: 10 * time.Second}}
	cmd := flag.Arg(0)

	var err error
	switch cmd {
	case "status":
		err = cmdStatus(cli)
	case "health":
		err = cmdHealth(cli)
	case "block":
		if flag.NArg() < 2 {
			fatalf("block requiere una IP como argumento")
		}
		err = cmdBlock(cli, flag.Arg(1))
	case "unblock":
		if flag.NArg() < 2 {
			fatalf("unblock requiere una IP como argumento")
		}
		err = cmdUnblock(cli, flag.Arg(1))
	case "urban":
		if flag.NArg() < 2 {
			fatalf("urban requiere una IP como argumento")
		}
		err = cmdUrban(cli, flag.Arg(1))
	case "queue":
		err = cmdQueue(cli)
	case "domains":
		err = cmdDomains(cli)
	case "whitelist":
		if flag.NArg() < 2 {
			fatalf("whitelist requiere un subcomando: list, add, remove")
		}
		switch flag.Arg(1) {
		case "list":
			err = cmdWhitelistList(cli)
		case "add":
			if flag.NArg() < 3 {
				fatalf("whitelist add requiere un valor (IP/CIDR o cuenta)")
			}
			err = cmdWhitelistAdd(cli, flag.Arg(2))
		case "remove":
			if flag.NArg() < 3 {
				fatalf("whitelist remove requiere un valor (IP/CIDR o cuenta)")
			}
			err = cmdWhitelistRemove(cli, flag.Arg(2))
		default:
			fatalf("subcomando desconocido: %q. Usa list, add o remove", flag.Arg(1))
		}
	default:
		fatalf("comando desconocido: %q. Usa -help para ver los disponibles.", cmd)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// --- comandos existentes ---

func cmdHealth(cli *apiClient) error {
	var body map[string]string
	if err := cli.get("/health", &body); err != nil {
		return fmt.Errorf("agente no responde: %w", err)
	}
	fmt.Printf("estado: %s  versión: %s\n", body["status"], body["version"])
	return nil
}

func cmdStatus(cli *apiClient) error {
	var body struct {
		Uptime     string `json:"uptime"`
		Version    string `json:"version"`
		BlockedIPs []struct {
			IP        string    `json:"ip"`
			ExpiresAt time.Time `json:"expires_at"`
			Module    string    `json:"module"`
			TTL       string    `json:"ttl"`
		} `json:"blocked_ips"`
		Stats struct {
			EventsTotal      int64 `json:"events_total"`
			AlertsTotal      int64 `json:"alerts_total"`
			BlocksTotal      int64 `json:"blocks_total"`
			SuspensionsTotal int64 `json:"suspensions_total"`
			RateLimitsTotal  int64 `json:"rate_limits_total"`
		} `json:"stats"`
	}
	if err := cli.get("/status", &body); err != nil {
		return err
	}

	fmt.Printf("SendGuard  versión: %s  uptime: %s\n\n", body.Version, body.Uptime)

	fmt.Printf("Contadores:\n")
	fmt.Printf("  eventos procesados : %d\n", body.Stats.EventsTotal)
	fmt.Printf("  alertas emitidas   : %d\n", body.Stats.AlertsTotal)
	fmt.Printf("  IPs bloqueadas     : %d\n", body.Stats.BlocksTotal)
	fmt.Printf("  cuentas suspendidas: %d\n", body.Stats.SuspensionsTotal)
	fmt.Printf("  rate-limits        : %d\n\n", body.Stats.RateLimitsTotal)

	if len(body.BlockedIPs) == 0 {
		fmt.Println("No hay IPs bloqueadas actualmente.")
		return nil
	}

	fmt.Printf("IPs bloqueadas (%d):\n", len(body.BlockedIPs))
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintf(w, "  IP\tMódulo\tTTL restante\n")
	fmt.Fprintf(w, "  --\t------\t------------\n")
	for _, b := range body.BlockedIPs {
		fmt.Fprintf(w, "  %s\t%s\t%s\n", b.IP, b.Module, b.TTL)
	}
	w.Flush()
	return nil
}

func cmdBlock(cli *apiClient, ip string) error {
	var body map[string]string
	if err := cli.do(http.MethodPost, "/blocked/"+ip, &body); err != nil {
		return err
	}
	fmt.Printf("IP bloqueada: %s\n", body["blocked"])
	return nil
}

func cmdUnblock(cli *apiClient, ip string) error {
	var body map[string]string
	if err := cli.do(http.MethodDelete, "/blocked/"+ip, &body); err != nil {
		return err
	}
	fmt.Printf("IP desbloqueada: %s\n", body["unblocked"])
	return nil
}

// --- nuevos comandos ---

func cmdUrban(cli *apiClient, ip string) error {
	var body struct {
		IP            string `json:"ip"`
		Country       string `json:"country"`
		CountryCode   string `json:"country_code"`
		AbuseScore    int    `json:"abuse_score"`
		TotalReports  int    `json:"total_reports"`
		IsWhitelisted bool   `json:"is_whitelisted"`
		AbuseError    string `json:"abuse_error"`
	}
	if err := cli.get("/urban/"+ip, &body); err != nil {
		return err
	}

	country := body.Country
	if country == "" {
		country = body.CountryCode
	}
	if country == "" {
		country = "(desconocido)"
	}

	whitelistedStr := "no"
	if body.IsWhitelisted {
		whitelistedStr = "sí"
	}

	fmt.Printf("IP:            %s\n", body.IP)
	fmt.Printf("País:          %s\n", country)
	fmt.Printf("Abuse Score:   %d/100\n", body.AbuseScore)
	fmt.Printf("Reportes:      %d\n", body.TotalReports)
	fmt.Printf("En whitelist:  %s\n", whitelistedStr)
	if body.AbuseError != "" {
		fmt.Printf("Aviso:         AbuseIPDB no disponible (%s)\n", body.AbuseError)
	}
	return nil
}

func cmdQueue(cli *apiClient) error {
	var body struct {
		Total   int `json:"total"`
		Entries []struct {
			ID         string   `json:"id"`
			Size       int      `json:"size"`
			Sender     string   `json:"sender"`
			Recipients []string `json:"recipients"`
		} `json:"entries"`
	}
	if err := cli.get("/queue", &body); err != nil {
		return err
	}

	if body.Total == 0 {
		fmt.Println("Cola de correo: vacía")
		return nil
	}

	fmt.Printf("Cola de correo: %d mensaje(s)\n\n", body.Total)
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintf(w, "  ID\tTamaño\tRemitente\tDestinatarios\n")
	fmt.Fprintf(w, "  --\t------\t---------\t-------------\n")
	for _, e := range body.Entries {
		rcpts := strings.Join(e.Recipients, ", ")
		if len(rcpts) > 60 {
			rcpts = rcpts[:57] + "..."
		}
		fmt.Fprintf(w, "  %s\t%d B\t%s\t%s\n", e.ID, e.Size, e.Sender, rcpts)
	}
	w.Flush()
	return nil
}

func cmdDomains(cli *apiClient) error {
	var body []struct {
		Domain string `json:"domain"`
		Alerts int64  `json:"alerts"`
	}
	if err := cli.get("/domains", &body); err != nil {
		return err
	}

	if len(body) == 0 {
		fmt.Println("Sin alertas por dominio registradas.")
		return nil
	}

	// Ordenar por alertas descendente
	sort.Slice(body, func(i, j int) bool {
		return body[i].Alerts > body[j].Alerts
	})

	fmt.Printf("Dominios con actividad sospechosa (%d):\n\n", len(body))
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintf(w, "  Dominio\tAlertas\n")
	fmt.Fprintf(w, "  -------\t-------\n")
	for _, d := range body {
		fmt.Fprintf(w, "  %s\t%d\n", d.Domain, d.Alerts)
	}
	w.Flush()
	return nil
}

func cmdWhitelistList(cli *apiClient) error {
	var body struct {
		IPs      []string `json:"ips"`
		Accounts []string `json:"accounts"`
	}
	if err := cli.get("/whitelist", &body); err != nil {
		return err
	}

	if len(body.IPs) == 0 && len(body.Accounts) == 0 {
		fmt.Println("Whitelist vacía.")
		return nil
	}

	sort.Strings(body.IPs)
	sort.Strings(body.Accounts)

	fmt.Printf("Whitelist actual:\n\n")
	fmt.Printf("  IPs/CIDRs (%d):\n", len(body.IPs))
	for _, ip := range body.IPs {
		fmt.Printf("    %s\n", ip)
	}
	fmt.Printf("\n  Cuentas (%d):\n", len(body.Accounts))
	for _, a := range body.Accounts {
		fmt.Printf("    %s\n", a)
	}
	return nil
}

func cmdWhitelistAdd(cli *apiClient, value string) error {
	var body map[string]string
	if err := cli.do(http.MethodPost, "/whitelist/"+value, &body); err != nil {
		return err
	}
	if ip, ok := body["added_ip"]; ok {
		fmt.Printf("IP/CIDR agregada a la whitelist: %s\n", ip)
		fmt.Println("Nota: cambio en memoria. Actualiza agent.yaml para que persista.")
	} else if acc, ok := body["added_account"]; ok {
		fmt.Printf("Cuenta agregada a la whitelist: %s\n", acc)
		fmt.Println("Nota: cambio en memoria. Actualiza agent.yaml para que persista.")
	}
	return nil
}

func cmdWhitelistRemove(cli *apiClient, value string) error {
	var body map[string]string
	if err := cli.do(http.MethodDelete, "/whitelist/"+value, &body); err != nil {
		return err
	}
	if ip, ok := body["removed_ip"]; ok {
		fmt.Printf("IP/CIDR eliminada de la whitelist: %s\n", ip)
	} else if acc, ok := body["removed_account"]; ok {
		fmt.Printf("Cuenta eliminada de la whitelist: %s\n", acc)
	}
	return nil
}

// --- cliente HTTP ---

type apiClient struct {
	baseURL string
	apiKey  string
	http    *http.Client
}

func (c *apiClient) get(path string, out any) error {
	return c.do(http.MethodGet, path, out)
}

func (c *apiClient) do(method, path string, out any) error {
	req, err := http.NewRequest(method, c.baseURL+path, nil)
	if err != nil {
		return fmt.Errorf("crear request: %w", err)
	}
	if c.apiKey != "" {
		req.Header.Set("X-Api-Key", c.apiKey)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("petición a %s%s: %w", c.baseURL, path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("acceso denegado (401) — usa -key para pasar la API key")
	}
	if resp.StatusCode == http.StatusServiceUnavailable {
		var errBody map[string]string
		json.NewDecoder(resp.Body).Decode(&errBody)
		return fmt.Errorf("función no disponible: %s", errBody["error"])
	}
	if resp.StatusCode >= 400 {
		var errBody map[string]string
		json.NewDecoder(resp.Body).Decode(&errBody)
		if msg, ok := errBody["error"]; ok {
			return fmt.Errorf("error %d: %s", resp.StatusCode, msg)
		}
		return fmt.Errorf("error HTTP %d", resp.StatusCode)
	}

	return json.NewDecoder(resp.Body).Decode(out)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}
