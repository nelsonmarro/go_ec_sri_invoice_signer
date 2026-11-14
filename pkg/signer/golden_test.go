package signer

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"testing"
	"time"
)

func loadTestKeyPair(t *testing.T) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	keyPEM, err := os.ReadFile("testdata/test_key.pem")
	if err != nil {
		t.Fatal(err)
	}
	certPEM, err := os.ReadFile("testdata/test_cert.pem")
	if err != nil {
		t.Fatal(err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	certBlock, _ := pem.Decode(certPEM)
	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return key, cert
}

// pinClockAndIDs makes signing deterministic: RSA PKCS#1 v1.5 has no randomness,
// so with a fixed clock and fixed IDs the signed document is byte-stable.
func pinClockAndIDs(t *testing.T) {
	t.Helper()
	origNow, origID := nowFunc, randomID
	n := 0
	nowFunc = func() time.Time { return time.Date(2026, 11, 14, 15, 30, 0, 0, time.UTC) }
	randomID = func() string { n++; return fmt.Sprintf("%08d", n) }
	t.Cleanup(func() { nowFunc, randomID = origNow, origID })
}

// The golden files were produced by v1.0.0, whose output the SRI accepts. Any
// input that was already in canonical form must keep signing to the same bytes.
func TestGoldenOutputMatchesV1(t *testing.T) {
	key, cert := loadTestKeyPair(t)

	cases := []struct {
		name, rootTag string
		algo          HashAlgorithm
	}{
		{"factura_sha1", "factura", SHA1},
		{"factura_sha256", "factura", SHA256},
		{"retencion_sha1", "comprobanteRetencion", SHA1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pinClockAndIDs(t)
			input, err := os.ReadFile("testdata/" + tc.rootTag + "_input.xml")
			if err != nil {
				t.Fatal(err)
			}
			got, err := signDocumentInternal(string(input), key, cert, tc.rootTag, tc.algo)
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			goldenPath := "testdata/" + tc.name + "_signed.golden.xml"
			if os.Getenv("UPDATE_GOLDEN") == "1" {
				if err := os.WriteFile(goldenPath, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(goldenPath)
			if err != nil {
				t.Fatal(err)
			}
			if got != string(want) {
				t.Errorf("signed output differs from the v1.0.0 golden %s", goldenPath)
			}
		})
	}
}
