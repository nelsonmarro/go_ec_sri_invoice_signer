package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

func TestSHA1(t *testing.T) {
	data := []byte("test data")
	// echo -n "test data" | openssl sha1 -binary | base64
	expected := "9I3YU4IIYIFsddVND1hNyGMyenw="

	hash := SHA1(data)
	if hash != expected {
		t.Errorf("expected %s, got %s", expected, hash)
	}
}

func TestSHA256(t *testing.T) {
	data := []byte("test data")
	// echo -n "test data" | openssl sha256 -binary | base64
	expected := "kW8AJ6V1B0znKjMXd8NHjWUT94alkb2JLaGld78jNfk="

	hash := SHA256(data)
	if hash != expected {
		t.Errorf("expected %s, got %s", expected, hash)
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

func TestGetIssuerName(t *testing.T) {
	cert := &x509.Certificate{
		Issuer: pkix.Name{
			CommonName:   "Test CA",
			Organization: []string{"Test Org"},
			Country:      []string{"EC"},
		},
	}

	// Go's String() output: "CN=Test CA,O=Test Org,C=EC" (with spaces after comma often depends on version/lib)
	// Our function removes spaces after commas.
	// We expect strict format without spaces after commas.
	// expected := "CN=Test CA,O=Test Org,C=EC"

	// Create a slightly more complex one to verify space removal if Go adds them
	// Note: pkix.Name.String() implementation varies, but let's assume it puts ", "
	// We manually verify the function behavior.
	name := GetIssuerName(cert)

	// We check that there are no ", " sequences
	if contains(name, ", ") {
		t.Errorf("Issuer name should not contain spaces after commas: %s", name)
	}
	// Basic content check
	if !contains(name, "CN=Test CA") {
		t.Errorf("Issuer name should contain CN: %s", name)
	}
}

func TestGetCertHash(t *testing.T) {
	// Create a dummy certificate
	cert := &x509.Certificate{
		Raw: []byte("dummy cert data"),
	}

	expected := SHA1(cert.Raw)
	hash := GetCertHash(cert)

	if hash != expected {
		t.Errorf("expected %s, got %s", expected, hash)
	}
}

func TestGetCertContent(t *testing.T) {
	cert := &x509.Certificate{
		Raw: []byte("dummy content"),
	}
	expected := "ZHVtbXkgY29udGVudA==" // base64 of "dummy content"

	content := GetCertContent(cert)
	if content != expected {
		t.Errorf("expected %s, got %s", expected, content)
	}
}

func TestParsePKCS12(t *testing.T) {
	// 1. Generate a key and certificate
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour),
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatal(err)
	}

	// 2. Encode to PKCS12
	password := "testpass"
	p12Data, err := pkcs12.Legacy.Encode(priv, cert, []*x509.Certificate{}, password)
	if err != nil {
		t.Fatal(err)
	}

	// 3. Test ParsePKCS12
	parsedKey, parsedCert, err := ParsePKCS12(p12Data, password)
	if err != nil {
		t.Fatalf("ParsePKCS12 failed: %v", err)
	}

	if parsedKey.N.Cmp(priv.N) != 0 {
		t.Error("Parsed key modulus does not match original")
	}
	if !parsedCert.Equal(cert) {
		t.Error("Parsed certificate does not match original")
	}

	// 4. Test wrong password
	_, _, err = ParsePKCS12(p12Data, "wrongpass")
	if err == nil {
		t.Error("expected error with wrong password")
	}
}

// Helper for go versions < 1.18 where strings.Contains is available but I want to be explicit
func contains(s, substr string) bool {
	for i := 0; i < len(s)-len(substr)+1; i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
