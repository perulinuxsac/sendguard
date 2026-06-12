package email

import (
	"strings"
	"testing"
)

func TestBuildUserNoticeDestinatarioEsLaCuenta(t *testing.T) {
	n := New(Config{From: "ti@perucloud.pe", UserNoticeFrom: "ti@perulinux.pe"})
	msg := n.buildUserNotice("jalegre@sedachimbote.com.pe", sampleAlert())

	if !strings.Contains(msg, "To: jalegre@sedachimbote.com.pe\r\n") {
		t.Error("el destinatario debe ser la propia cuenta suspendida")
	}
	if !strings.Contains(msg, "From: Seguridad del Correo <ti@perulinux.pe>") {
		t.Error("el From debe ser el remitente del aviso (user_notice_from), no el de admins")
	}
}

func TestUserNoticeFromFallback(t *testing.T) {
	// Sin user_notice_from configurado, se usa el from general.
	n := New(Config{From: "ti@perucloud.pe"})
	msg := n.buildUserNotice("user@cliente.pe", sampleAlert())

	if !strings.Contains(msg, "From: Seguridad del Correo <ti@perucloud.pe>") {
		t.Error("sin user_notice_from el remitente debe ser el from general")
	}
}

func TestBuildUserNoticeContenido(t *testing.T) {
	n := New(Config{From: "ti@perulinux.pe"})
	alert := sampleAlert()
	msg := n.buildUserNotice("user@cliente.pe", alert)

	for _, want := range []string{
		"Alerta de seguridad",         // titular (texto y HTML)
		"SUSPENDIDA",                  // texto plano: qué pasó
		"Cambie su contraseña",        // qué hacer
		alert.IP,                      // IP del abuso
		"multipart/alternative",       // MIME con parte HTML
		"actividad sospechosa",        // subtítulo HTML
		`mailto:ti@perulinux.pe`,      // botón de contacto al soporte
		"#1a73e8",                     // botón azul estilo Google
		"Recibió este mensaje porque", // pie gris
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("el aviso debe contener %q", want)
		}
	}
	// No es la alerta técnica de admins: no debe filtrar el nombre del módulo.
	if strings.Contains(msg, alert.Module) {
		t.Errorf("el aviso al usuario no debe incluir detalles técnicos como el módulo %q", alert.Module)
	}
}

func TestBuildUserNoticeSinIP(t *testing.T) {
	n := New(Config{From: "ti@perulinux.pe"})
	alert := sampleAlert()
	alert.IP = ""
	msg := n.buildUserNotice("user@cliente.pe", alert)

	if strings.Contains(msg, "IP que originó el abuso") {
		t.Error("sin IP en la alerta no debe aparecer la línea de IP")
	}
}
