package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"os"
	"testing"
)

func TestSHA1(t *testing.T) {
	data := []byte("test data")
	expected := "9I3YU4IIYIFsddVND1hNyGMyenw=" // echo -n "test data" | openssl sha1 -binary | base64

	hash := SHA1(data)
	if hash != expected {
		t.Errorf("expected %s, got %s", expected, hash)
	}
}

func TestParsePKCS12(t *testing.T) {
	// Assuming test runs from project root or we locate testdata relative to package
	// Usually go test runs in package dir.
	
	// Let's try to locate it relative to module root for stability
	p12Path := "../../testdata/test.p12"
	
	p12Bytes, err := os.ReadFile(p12Path)
	if err != nil {
		t.Skipf("skipping PKCS12 test, file not found at %s: %v", p12Path, err)
		return
	}

	key, cert, err := ParsePKCS12(p12Bytes, "testing123")
	if err != nil {
		t.Fatalf("ParsePKCS12 failed: %v", err)
	}

	if key == nil {
		t.Error("expected private key, got nil")
	}
	if cert == nil {
		t.Error("expected certificate, got nil")
	}
}

func TestSign(t *testing.T) {
	// Generate a temporary key for pure unit testing without file IO
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("content to sign")
	sig, err := Sign(data, key)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if sig == "" {
		t.Error("expected signature, got empty string")
	}
}

func TestGetPrivateKeyData(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	mod, exp := GetPrivateKeyData(key)
	if mod == "" {
		t.Error("expected modulus")
	}
	if exp == "" {
		t.Error("expected exponent")
	}
}
