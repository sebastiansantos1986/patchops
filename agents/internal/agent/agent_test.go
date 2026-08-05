package agent

import "testing"

func TestSupportedPlatform(t *testing.T) {
	if err := New("darwin").Run(t.Context(), true); err != nil { t.Fatal(err) }
}

func TestUnsupportedPlatform(t *testing.T) {
	if err := New("plan9").Run(t.Context(), true); err == nil { t.Fatal("expected unsupported platform error") }
}
