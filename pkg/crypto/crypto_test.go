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

// newCert issues a certificate for pub, signed by parent/parentKey (self-signed when parent is nil).
func newCert(t *testing.T, serial int64, cn string, pub *rsa.PublicKey, parent *x509.Certificate, parentKey *rsa.PrivateKey, isCA bool) *x509.Certificate {
	t.Helper()
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  isCA,
		BasicConstraintsValid: true,
	}
	if parent == nil {
		parent = tpl
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, parent, pub, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// Ecuadorian CAs (Security Data, UANATACA, Banco Central) ship .p12 files that
// carry the issuing chain next to the signer certificate.
func TestParsePKCS12WithCertificateChain(t *testing.T) {
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	root := newCert(t, 1, "Test Root CA", &caKey.PublicKey, nil, caKey, true)
	sub := newCert(t, 2, "Test Sub CA", &caKey.PublicKey, root, caKey, true)
	leaf := newCert(t, 3, "Test Signer", &signerKey.PublicKey, sub, caKey, false)

	encoders := map[string]*pkcs12.Encoder{"legacy": pkcs12.Legacy, "modern": pkcs12.Modern}
	for name, enc := range encoders {
		t.Run(name+"/signer certificate first", func(t *testing.T) {
			data, err := enc.Encode(signerKey, leaf, []*x509.Certificate{sub, root}, "pw")
			if err != nil {
				t.Fatal(err)
			}
			key, cert, err := ParsePKCS12(data, "pw")
			if err != nil {
				t.Fatalf("ParsePKCS12 failed on a .p12 with a chain: %v", err)
			}
			if !cert.Equal(leaf) || key.N.Cmp(signerKey.N) != 0 {
				t.Errorf("got certificate %q, want the signer certificate", cert.Subject.CommonName)
			}
		})
		t.Run(name+"/signer certificate not first", func(t *testing.T) {
			// The file lists a CA certificate where the signer's is expected.
			data, err := enc.Encode(signerKey, root, []*x509.Certificate{sub, leaf}, "pw")
			if err != nil {
				t.Fatal(err)
			}
			_, cert, err := ParsePKCS12(data, "pw")
			if err != nil {
				t.Fatalf("ParsePKCS12 failed: %v", err)
			}
			if !cert.Equal(leaf) {
				t.Errorf("got certificate %q, want the one matching the private key", cert.Subject.CommonName)
			}
		})
	}

	t.Run("no certificate matches the key", func(t *testing.T) {
		data, err := pkcs12.Modern.Encode(signerKey, root, []*x509.Certificate{sub}, "pw")
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := ParsePKCS12(data, "pw"); err == nil {
			t.Error("want an error when no certificate belongs to the private key")
		}
	})
}

func TestGetIssuerNameIsRFC2253(t *testing.T) {
	tests := []struct {
		name   string
		issuer pkix.Name
		want   string
	}{
		{
			name:   "plain",
			issuer: pkix.Name{CommonName: "Test CA", Organization: []string{"Test Org"}, Country: []string{"EC"}},
			want:   "CN=Test CA,O=Test Org,C=EC",
		},
		{
			// A comma inside a value is escaped; the space after it belongs to the value.
			name:   "comma and space inside a value",
			issuer: pkix.Name{CommonName: "AC ACME", Organization: []string{"ACME, S.A."}, Country: []string{"EC"}},
			want:   `CN=AC ACME,O=ACME\, S.A.,C=EC`,
		},
		{
			name:   "real-world shape",
			issuer: pkix.Name{CommonName: "AUTORIDAD DE CERTIFICACION SUBCA-2 SECURITY DATA", OrganizationalUnit: []string{"ENTIDAD DE CERTIFICACION DE INFORMACION"}, Organization: []string{"SECURITY DATA S.A. 2"}, Country: []string{"EC"}},
			want:   "CN=AUTORIDAD DE CERTIFICACION SUBCA-2 SECURITY DATA,OU=ENTIDAD DE CERTIFICACION DE INFORMACION,O=SECURITY DATA S.A. 2,C=EC",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetIssuerName(&x509.Certificate{Issuer: tt.issuer}); got != tt.want {
				t.Errorf("GetIssuerName() = %q, want %q", got, tt.want)
			}
		})
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
