package enforcement

import (
	"testing"
)

// samplePostqueue es la salida típica de `postqueue -p` con tres mensajes:
//   - A1B2C: a user@example.com (dominio objetivo)
//   - D3E4F: a otro@other.org   (dominio distinto)
//   - G5H6I: dos rcpt, uno a sub@example.com y otro a x@third.net
var samplePostqueue = []byte(`
-Queue ID-  --Size-- ----Arrival Time---- -Sender/Recipient-------
A1B2C3D4E*     1234 Sat May 11 10:00:00  sender@source.com
                                         user@example.com

F5G6H7I8J!     5678 Sat May 11 10:01:00  otro@source.com
                                         otro@other.org

K9L0M1N2O*      999 Sat May 11 10:02:00  bulk@source.com
                                         sub@example.com
                                         x@third.net

-- 3 Kbytes in 3 Requests.
`)

func TestExtractQueueIDsEncontrado(t *testing.T) {
	ids := extractQueueIDs([]byte(samplePostqueue), "example.com")
	if len(ids) != 2 {
		t.Fatalf("se esperaban 2 IDs para example.com, got %d: %v", len(ids), ids)
	}
	// A1B2C3D4E y K9L0M1N2O deben aparecer (sin * ni !)
	found := map[string]bool{}
	for _, id := range ids {
		found[id] = true
	}
	if !found["A1B2C3D4E"] {
		t.Error("A1B2C3D4E debe estar en los IDs para example.com")
	}
	if !found["K9L0M1N2O"] {
		t.Error("K9L0M1N2O debe estar en los IDs para example.com (sub@example.com)")
	}
}

func TestExtractQueueIDsNoEncontrado(t *testing.T) {
	ids := extractQueueIDs([]byte(samplePostqueue), "nodomain.xyz")
	if len(ids) != 0 {
		t.Fatalf("se esperaban 0 IDs para nodomain.xyz, got %d", len(ids))
	}
}

func TestExtractQueueIDsDominioDistinto(t *testing.T) {
	ids := extractQueueIDs([]byte(samplePostqueue), "other.org")
	if len(ids) != 1 {
		t.Fatalf("se esperaba 1 ID para other.org, got %d", len(ids))
	}
	if ids[0] != "F5G6H7I8J" {
		t.Errorf("ID: got %q, want F5G6H7I8J", ids[0])
	}
}

func TestExtractQueueIDsSinArroba(t *testing.T) {
	// Pasar el dominio con @ delante no debe importar.
	ids := extractQueueIDs([]byte(samplePostqueue), "@example.com")
	if len(ids) != 2 {
		t.Fatalf("con @example.com se esperaban 2 IDs, got %d", len(ids))
	}
}

func TestExtractQueueIDsSinPrefixoDuplicado(t *testing.T) {
	// Un mensaje con 2 rcpt en example.com no debe aparecer dos veces.
	data := []byte(`
A0000FFFFF*     100 Mon Jan  1 00:00:00  s@s.com
                                         rcpt1@example.com
                                         rcpt2@example.com

`)
	ids := extractQueueIDs(data, "example.com")
	if len(ids) != 1 {
		t.Fatalf("un mensaje con 2 rcpt del mismo dominio debe contar una sola vez, got %d", len(ids))
	}
}

func TestExtractQueueIDsVacio(t *testing.T) {
	ids := extractQueueIDs([]byte("Mail queue is empty\n"), "example.com")
	if len(ids) != 0 {
		t.Fatalf("cola vacía debe retornar 0 IDs, got %d", len(ids))
	}
}

func TestExtractQueueIDsStripSuffix(t *testing.T) {
	// El * y ! al final del ID deben eliminarse.
	data := []byte(`
AABBCCDD11*     100 Mon Jan  1 00:00:00  s@s.com
                                         u@strip.com

EEFF001122!     200 Mon Jan  1 00:01:00  s@s.com
                                         v@strip.com

`)
	ids := extractQueueIDs(data, "strip.com")
	if len(ids) != 2 {
		t.Fatalf("se esperaban 2 IDs, got %d", len(ids))
	}
	for _, id := range ids {
		if id[len(id)-1] == '*' || id[len(id)-1] == '!' {
			t.Errorf("ID no debe terminar en * o !: %q", id)
		}
	}
}

func TestExtractQueueIDsCaseInsensitive(t *testing.T) {
	data := []byte(`
CASEID00001*     100 Mon Jan  1 00:00:00  s@s.com
                                         User@EXAMPLE.COM

`)
	ids := extractQueueIDs(data, "example.com")
	if len(ids) != 1 {
		t.Fatalf("la comparación debe ser case-insensitive, got %d IDs", len(ids))
	}
}
