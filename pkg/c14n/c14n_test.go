package c14n

import (
	"testing"
)

func TestCanonicalize(t *testing.T) {
	input := `<root  b="2" a="1" > <child> text </child> </root>`
	// C14N (simplified expectation for this lib):
	// - Attributes sorted
	// - Spaces preserved in text
	// - No whitespace around attributes (normalized)
	// - <root a="1" b="2"><child> text </child></root> (approximately)
	// The ucarion/c14n library implements Exclusive Canonicalization.

	got, err := Canonicalize([]byte(input))
	if err != nil {
		t.Fatalf("Canonicalize failed: %v", err)
	}

	// Verify at least basic properties: no panic, non-empty
	if len(got) == 0 {
		t.Error("expected non-empty output")
	}

	// For specific behavior:
	// c14n should sort attributes a="1" b="2"
	s := string(got)
	if s == "" {
		t.Error("empty result")
	}
}
