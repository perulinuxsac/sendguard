package parser

import (
	"testing"
	"time"
)

// Tests internos de parseTimestamp (no exportado).
func TestParseTimestampISOConZona(t *testing.T) {
	got := parseTimestamp("2024-05-11T10:23:45.123+05:00")
	want := time.Date(2024, 5, 11, 10, 23, 45, 123_000_000, time.FixedZone("", 5*3600))
	if !got.Equal(want) {
		t.Errorf("ISO con zona: got %v, want %v", got, want)
	}
}

func TestParseTimestampISOConZ(t *testing.T) {
	got := parseTimestamp("2024-05-11T10:23:45Z")
	want := time.Date(2024, 5, 11, 10, 23, 45, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("ISO con Z: got %v, want %v", got, want)
	}
}

// Regresión: "2024-05-11T10:23:45" (ISO sin zona ni fracción) no matcheaba
// ningún layout y caía a time.Now(). Debe parsearse en hora local, igual que
// el syslog clásico y mailbox.log.
func TestParseTimestampISOSinZona(t *testing.T) {
	got := parseTimestamp("2024-05-11T10:23:45")
	want := time.Date(2024, 5, 11, 10, 23, 45, 0, time.Local)
	if !got.Equal(want) {
		t.Errorf("ISO sin zona: got %v, want %v", got, want)
	}
}

func TestParseTimestampISOSinZonaConFraccion(t *testing.T) {
	got := parseTimestamp("2024-05-11T10:23:45.500")
	want := time.Date(2024, 5, 11, 10, 23, 45, 500_000_000, time.Local)
	if !got.Equal(want) {
		t.Errorf("ISO sin zona con fracción: got %v, want %v", got, want)
	}
}

func TestParseTimestampEspacioSinZona(t *testing.T) {
	// Variante con espacio en vez de T (permitida por reHeader) — hora local,
	// no UTC como antes del fix.
	got := parseTimestamp("2024-05-11 10:23:45")
	want := time.Date(2024, 5, 11, 10, 23, 45, 0, time.Local)
	if !got.Equal(want) {
		t.Errorf("espacio sin zona: got %v, want %v", got, want)
	}
}

func TestParseTimestampSyslogClasico(t *testing.T) {
	got := parseTimestamp("May 11 10:23:45")
	if got.Month() != time.May || got.Day() != 11 || got.Hour() != 10 ||
		got.Minute() != 23 || got.Second() != 45 {
		t.Errorf("syslog clásico: got %v", got)
	}
	if got.Location() != time.Now().Location() {
		t.Errorf("syslog clásico debe usar zona local: got %v", got.Location())
	}
}

func TestParseTimestampInvalido(t *testing.T) {
	before := time.Now()
	got := parseTimestamp("no-es-un-timestamp")
	after := time.Now()
	if got.Before(before) || got.After(after) {
		t.Errorf("timestamp inválido debe caer a time.Now(): got %v", got)
	}
}
