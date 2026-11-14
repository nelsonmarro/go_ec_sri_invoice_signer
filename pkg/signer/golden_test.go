package signer

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"testing"
	"time"
)

var (
	testKeyOnce sync.Once
	testKey     *rsa.PrivateKey
	testCert    *x509.Certificate
	testKeyErr  error
)

// loadTestKeyPair returns a key pair generated once per test run. The
// certificate carries the same subject, serial and validity as the one the
// v1.0.0 golden files were signed with, so only key-derived values differ.
func loadTestKeyPair(t *testing.T) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	testKeyOnce.Do(func() {
		testKey, testKeyErr = rsa.GenerateKey(rand.Reader, 2048)
		if testKeyErr != nil {
			return
		}
		tpl := x509.Certificate{
			SerialNumber: big.NewInt(20261114),
			Subject:      pkix.Name{CommonName: "TEST ONLY - NOT A REAL SIGNER", Organization: []string{"go_ec_sri_invoice_signer tests"}, Country: []string{"EC"}},
			NotBefore:    time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
			NotAfter:     time.Date(2120, 1, 1, 0, 0, 0, 0, time.UTC),
			KeyUsage:     x509.KeyUsageDigitalSignature,
		}
		var der []byte
		der, testKeyErr = x509.CreateCertificate(rand.Reader, &tpl, &tpl, &testKey.PublicKey, testKey)
		if testKeyErr != nil {
			return
		}
		testCert, testKeyErr = x509.ParseCertificate(der)
	})
	if testKeyErr != nil {
		t.Fatal(testKeyErr)
	}
	return testKey, testCert
}

// writeTestCertPEM saves the test certificate where an external verifier can read it.
func writeTestCertPEM(t *testing.T) string {
	t.Helper()
	_, cert := loadTestKeyPair(t)
	path := filepath.Join(t.TempDir(), "cert.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// pinClockAndIDs fixes the signing time and the generated IDs.
func pinClockAndIDs(t *testing.T) {
	t.Helper()
	origNow, origID := nowFunc, randomID
	n := 0
	nowFunc = func() time.Time { return time.Date(2026, 11, 14, 15, 30, 0, 0, time.UTC) }
	randomID = func() string { n++; return fmt.Sprintf("%08d", n) }
	t.Cleanup(func() { nowFunc, randomID = origNow, origID })
}

var (
	documentDigestRe = regexp.MustCompile(`URI="#comprobante"><ds:Transforms>.*?</ds:Transforms><ds:DigestMethod [^>]*></ds:DigestMethod><ds:DigestValue>([^<]*)</ds:DigestValue>`)
	keyDerivedRe     = regexp.MustCompile(`(<ds:(?:DigestValue|SignatureValue|X509Certificate|Modulus)(?: [^>]*)?>)[^<]*`)
)

// withoutKeyMaterial blanks the values that depend on the signing key or
// certificate: digests, signature value, certificate and modulus.
func withoutKeyMaterial(signed string) string {
	return keyDerivedRe.ReplaceAllString(signed, "${1}KEY-DERIVED")
}

func documentDigest(t *testing.T, signed string) string {
	t.Helper()
	m := documentDigestRe.FindStringSubmatch(signed)
	if m == nil {
		t.Fatal("document reference not found")
	}
	return m[1]
}

// The golden files were produced by v1.0.0, whose output the SRI accepts. An
// input that was already in canonical form must keep producing the same signed
// document: same bytes around the key-derived values and, above all, the same
// document digest, which does not depend on the key.
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
			golden, err := os.ReadFile("testdata/" + tc.name + "_signed.golden.xml")
			if err != nil {
				t.Fatal(err)
			}
			want := string(golden)

			if g, w := documentDigest(t, got), documentDigest(t, want); g != w {
				t.Errorf("document digest = %s, v1.0.0 produced %s", g, w)
			}
			if withoutKeyMaterial(got) != withoutKeyMaterial(want) {
				t.Errorf("signed output differs from the v1.0.0 golden:\n got: %s\nwant: %s", withoutKeyMaterial(got), withoutKeyMaterial(want))
			}
		})
	}
}
