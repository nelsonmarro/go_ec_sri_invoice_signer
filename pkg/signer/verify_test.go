package signer

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	dsig "github.com/russellhaering/goxmldsig"
	"software.sslmate.com/src/go-pkcs12"
)

const sampleInvoice = `<factura id="comprobante" version="1.1.0"><info>contenido</info><total>115.00</total></factura>`

func signSample(t *testing.T, algo HashAlgorithm) string {
	t.Helper()
	key, cert := loadTestKeyPair(t)
	signed, err := signDocumentInternal(sampleInvoice, key, cert, "factura", algo)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed
}

func TestVerifyAcceptsSignedDocuments(t *testing.T) {
	for _, algo := range []HashAlgorithm{SHA1, SHA256} {
		if err := Verify(signSample(t, algo)); err != nil {
			t.Errorf("algo %d: Verify rejected a freshly signed document: %v", algo, err)
		}
	}
}

func TestVerifyAcceptsV1GoldenDocuments(t *testing.T) {
	for _, name := range []string{"factura_sha1", "factura_sha256", "retencion_sha1"} {
		golden, err := os.ReadFile("testdata/" + name + "_signed.golden.xml")
		if err != nil {
			t.Fatal(err)
		}
		if err := Verify(string(golden)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestVerifyRejectsTampering(t *testing.T) {
	signed := signSample(t, SHA1)

	replaceOnce := func(old, new string) string {
		if strings.Count(signed, old) != 1 {
			t.Fatalf("fixture must contain %q exactly once", old)
		}
		return strings.Replace(signed, old, new, 1)
	}
	// Flip one base64 character of the first startTag element found after anchor.
	flipIn := func(anchor, startTag string) string {
		a := strings.Index(signed, anchor)
		if a < 0 {
			t.Fatalf("fixture has no %s", anchor)
		}
		i := strings.Index(signed[a:], startTag)
		if i < 0 {
			t.Fatalf("fixture has no %s after %s", startTag, anchor)
		}
		i = a + i + len(startTag)
		i += strings.Index(signed[i:], ">") + 1
		c := byte('A')
		if signed[i] == 'A' {
			c = 'B'
		}
		return signed[:i] + string(c) + signed[i+1:]
	}

	cases := []struct {
		name, doc, wantInError string
	}{
		{"document content changed", replaceOnce("<total>115.00</total>", "<total>915.00</total>"), `"#comprobante"`},
		{"element added to the document", replaceOnce("<info>", "<extra></extra><info>"), `"#comprobante"`},
		{"signing time changed", replaceOnce("<etsi:SigningTime>20", "<etsi:SigningTime>19"), "Signature-SignedProperties"},
		{"certificate swapped in KeyInfo", flipIn("<ds:KeyInfo", "<ds:Modulus"), "Certificate"},
		{"document digest replaced", flipIn(`<ds:Reference Id="Reference-ID-`, "<ds:DigestValue"), `"#comprobante"`},
		{"signature value corrupted", flipIn("<ds:SignedInfo", "<ds:SignatureValue"), "signature value"},
		{"signature removed", signed[:strings.Index(signed, "<ds:Signature ")] + "</factura>", "no ds:Signature"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := Verify(tc.doc)
			if !errors.Is(err, ErrInvalidSignature) {
				t.Fatalf("want ErrInvalidSignature, got %v", err)
			}
			if !strings.Contains(err.Error(), tc.wantInError) {
				t.Errorf("error %q should mention %q", err, tc.wantInError)
			}
		})
	}
}

func TestVerifyRejectsSignatureThatDoesNotCoverTheDocument(t *testing.T) {
	// A cryptographically valid signature whose references skip the document:
	// the document reference is re-pointed at KeyInfo and SignedInfo is re-signed.
	key, _ := loadTestKeyPair(t)
	root, err := parseRootElement(cleanXMLString(signSample(t, SHA1)))
	if err != nil {
		t.Fatal(err)
	}
	signature := childByTag(root, "Signature")
	signedInfo := childByTag(signature, "SignedInfo")
	refs := childrenByTag(signedInfo, "Reference")
	keyInfoRef, docRef := refs[1], refs[2]
	docRef.SelectAttr("URI").Value = keyInfoRef.SelectAttrValue("URI", "")
	docRef.RemoveChild(childByTag(docRef, "Transforms"))
	childByTag(docRef, "DigestValue").SetText(childByTag(keyInfoRef, "DigestValue").Text())

	canon := dsig.MakeC14N10RecCanonicalizer()
	siCanonical, err := canon.Canonicalize(signedInfo)
	if err != nil {
		t.Fatal(err)
	}
	sigValue, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA1, sum(crypto.SHA1, siCanonical))
	if err != nil {
		t.Fatal(err)
	}
	childByTag(signature, "SignatureValue").SetText(base64.StdEncoding.EncodeToString(sigValue))
	forged, err := canon.Canonicalize(root)
	if err != nil {
		t.Fatal(err)
	}

	err = Verify(string(forged))
	if !errors.Is(err, ErrInvalidSignature) || !strings.Contains(err.Error(), "document root") {
		t.Fatalf("want ErrInvalidSignature about the document root, got %v", err)
	}
}

func TestVerifyRejectsGarbage(t *testing.T) {
	for _, doc := range []string{"", "not xml", "<factura>", `<?xml version="1.0"?>`} {
		if err := Verify(doc); err == nil {
			t.Errorf("Verify(%q) should fail", doc)
		}
	}
}

func TestSignRejectsUnexpectedRoot(t *testing.T) {
	key, cert := loadTestKeyPair(t)
	_, err := signDocumentInternal(`<notaCredito id="comprobante"></notaCredito>`, key, cert, "factura", SHA1)
	if err == nil || !strings.Contains(err.Error(), "<notaCredito>") || !strings.Contains(err.Error(), "<factura>") {
		t.Errorf("want an error naming both root tags, got %v", err)
	}
}

func TestSignRejectsDocumentWithoutRoot(t *testing.T) {
	key, cert := loadTestKeyPair(t)
	for _, doc := range []string{"", `<?xml version="1.0" encoding="UTF-8"?>`, "   "} {
		if _, err := signDocumentInternal(doc, key, cert, "factura", SHA1); err == nil {
			t.Errorf("signing %q should fail", doc)
		}
	}
}

func TestSignKeepsExistingRootID(t *testing.T) {
	key, cert := loadTestKeyPair(t)
	signed, err := signDocumentInternal(`<factura id="doc-7"><info>x</info></factura>`, key, cert, "factura", SHA1)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(signed, `URI="#doc-7"`) || strings.Contains(signed, `URI="#comprobante"`) {
		t.Error("the document reference must point at the root's own id")
	}
}

func TestSignAddsDefaultRootID(t *testing.T) {
	key, cert := loadTestKeyPair(t)
	signed, err := signDocumentInternal(`<factura><info>x</info></factura>`, key, cert, "factura", SHA1)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(signed, `<factura id="comprobante">`) || !strings.Contains(signed, `URI="#comprobante"`) {
		t.Errorf("missing default id on root or reference:\n%s", signed)
	}
}

func TestSignedOutputKeepsSRIStructure(t *testing.T) {
	signed := signSample(t, SHA1)
	if !strings.HasPrefix(signed, `<?xml version="1.0" encoding="UTF-8" standalone="no"?>`+"\n<factura ") {
		t.Error("signed document must start with the XML header followed by the root")
	}
	if !strings.HasSuffix(signed, "</ds:Signature></factura>") {
		t.Error("the signature must be the last child of the root")
	}
	order := []string{"<ds:SignedInfo ", "<ds:SignatureValue ", "<ds:KeyInfo ", "<ds:Object "}
	last := -1
	for _, tag := range order {
		i := strings.Index(signed, tag)
		if i <= last {
			t.Fatalf("%s is missing or out of order", tag)
		}
		last = i
	}
}

// p12For builds a PKCS#12 file holding a fresh key and a certificate with the given validity.
func p12For(t *testing.T, notBefore, notAfter time.Time) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tpl := x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "Test Signer"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tpl, &tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	data, err := pkcs12.Modern.Encode(key, cert, nil, "secret")
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestSignChecksCertificateValidity(t *testing.T) {
	now := time.Now()
	opts := &SignOptions{Password: "secret"}

	t.Run("valid", func(t *testing.T) {
		signed, err := Sign(sampleInvoice, p12For(t, now.Add(-time.Hour), now.Add(time.Hour)), RootInvoice, opts)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		if err := Verify(signed); err != nil {
			t.Errorf("Verify: %v", err)
		}
	})
	t.Run("expired", func(t *testing.T) {
		_, err := SignInvoice(sampleInvoice, p12For(t, now.Add(-48*time.Hour), now.Add(-24*time.Hour)), opts)
		if !errors.Is(err, ErrCertificateExpired) {
			t.Errorf("want ErrCertificateExpired, got %v", err)
		}
	})
	t.Run("not yet valid", func(t *testing.T) {
		_, err := SignInvoice(sampleInvoice, p12For(t, now.Add(24*time.Hour), now.Add(48*time.Hour)), opts)
		if !errors.Is(err, ErrCertificateNotYetValid) {
			t.Errorf("want ErrCertificateNotYetValid, got %v", err)
		}
	})
	t.Run("wrong password", func(t *testing.T) {
		_, err := SignInvoice(sampleInvoice, p12For(t, now.Add(-time.Hour), now.Add(time.Hour)), &SignOptions{Password: "nope"})
		if err == nil {
			t.Error("want an error for a wrong password")
		}
	})
}

func TestTypedSignersUseTheirRootTag(t *testing.T) {
	now := time.Now()
	p12 := p12For(t, now.Add(-time.Hour), now.Add(time.Hour))
	opts := &SignOptions{Password: "secret"}
	signers := map[string]func(string, []byte, *SignOptions) (string, error){
		"factura":              SignInvoice,
		"notaCredito":          SignCreditNote,
		"notaDebito":           SignDebitNote,
		"guiaRemision":         SignDeliveryGuide,
		"comprobanteRetencion": SignWithholdingCertificate,
		"liquidacionCompra":    SignPurchaseSettlement,
	}
	for root, sign := range signers {
		doc := "<" + root + ` id="comprobante"><info>x</info></` + root + ">"
		signed, err := sign(doc, p12, opts)
		if err != nil {
			t.Errorf("%s: %v", root, err)
			continue
		}
		if err := Verify(signed); err != nil {
			t.Errorf("%s: %v", root, err)
		}
		if _, err := sign("<otro></otro>", p12, opts); err == nil {
			t.Errorf("%s signer accepted a foreign root", root)
		}
	}
}

func TestSignFailsWhenSelfVerificationFails(t *testing.T) {
	orig := selfVerify
	selfVerify = func(string) error { return ErrInvalidSignature }
	t.Cleanup(func() { selfVerify = orig })

	key, cert := loadTestKeyPair(t)
	signed, err := signDocumentInternal(sampleInvoice, key, cert, "factura", SHA1)
	if !errors.Is(err, ErrInvalidSignature) || signed != "" {
		t.Errorf("want no document and ErrInvalidSignature, got %q, %v", signed, err)
	}
}
