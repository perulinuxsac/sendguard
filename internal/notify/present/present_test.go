package present

import (
	"strings"
	"testing"

	"github.com/perulinux/sendguard/internal/detection"
)

func TestTituloSegunResultadoReal(t *testing.T) {
	cases := []struct {
		action  detection.Action
		outcome detection.Outcome
		title   string
		tone    Tone
		revert  bool
	}{
		{detection.ActionSuspendAcct, detection.OutcomeApplied, "Cuenta suspendida", ToneCritical, true},
		{detection.ActionSuspendAcct, "", "Cuenta suspendida", ToneCritical, true}, // sin evaluar
		{detection.ActionSuspendAcct, detection.OutcomeFailed, "FALLÓ la suspensión de la cuenta", ToneFailed, false},
		{detection.ActionSuspendAcct, detection.OutcomeSkipped, "Suspensión omitida — revisar", ToneWarning, false},
		{detection.ActionSuspendAcct, detection.OutcomeAlready, "Cuenta ya suspendida — nueva actividad", ToneMuted, true},
		{detection.ActionBlockIP, detection.OutcomeApplied, "IP bloqueada", ToneHigh, true},
		{detection.ActionBlockIP, detection.OutcomeFailed, "FALLÓ el bloqueo de IP", ToneFailed, false},
		{detection.ActionBlockIP, detection.OutcomeSkipped, "Bloqueo omitido — revisar", ToneWarning, false},
		{detection.ActionBlockIP, detection.OutcomeAlready, "IP ya bloqueada", ToneMuted, true},
	}
	for _, c := range cases {
		v := Build(detection.Alert{Action: c.action, Outcome: c.outcome, IP: "1.2.3.4", Account: "u@d.pe"})
		if v.Title != c.title || v.Tone != c.tone || (v.Revert != "") != c.revert {
			t.Errorf("%s/%s: got %q tone=%d revert=%q", c.action, c.outcome, v.Title, v.Tone, v.Revert)
		}
	}
}

func TestObjetivoPrincipal(t *testing.T) {
	a := detection.Alert{IP: "1.2.3.4", Account: "u@d.pe"}
	a.Action = detection.ActionSuspendAcct
	if Build(a).Target != "u@d.pe" {
		t.Error("una suspensión apunta a la cuenta")
	}
	a.Action = detection.ActionBlockIP
	if Build(a).Target != "1.2.3.4" {
		t.Error("un bloqueo apunta a la IP")
	}
}

func TestFallidaIndicaComoActuar(t *testing.T) {
	v := Build(detection.Alert{Action: detection.ActionSuspendAcct, Outcome: detection.OutcomeFailed, Account: "u@d.pe"})
	if !strings.Contains(v.Next, "sigue ACTIVA") || !strings.Contains(v.Next, "zmprov ma u@d.pe zimbraAccountStatus locked") {
		t.Errorf("Next: %q", v.Next)
	}
}

func TestFlag(t *testing.T) {
	for in, want := range map[string]string{"PE": "🇵🇪", "us": "🇺🇸", "": "", "PER": "", "1A": ""} {
		if got := Flag(in); got != want {
			t.Errorf("Flag(%q) = %q, want %q", in, got, want)
		}
	}
	if Country("pe") != "🇵🇪 PE" {
		t.Errorf("Country: %q", Country("pe"))
	}
}

func TestModuleNameCubreTodosLosModulos(t *testing.T) {
	for _, m := range []string{"auth_failed", "number_messages", "sasl_connections", "dist_brute_force",
		"impossible_traveler", "queue_monitor", "domain_discovery", "bounce_rate", "rcpt_flood",
		"password_spray", "account_takeover"} {
		if ModuleName(m) == m {
			t.Errorf("módulo %s sin descripción legible", m)
		}
	}
}
