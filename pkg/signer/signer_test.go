package signer

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/xml"
	"math/big"
	"strings"
	"testing"
	"time"

	libcrypto "github.com/nelsonmarro/go_ec_sri_invoice_signer/pkg/crypto"
)

// Helper to generate a dummy certificate/key pair for testing
func generateTestKeys() (*rsa.PrivateKey, *x509.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test User",
			Organization: []string{"Test Org"},
			Country:      []string{"EC"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour),
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, err
	}

	return key, cert, nil
}

func TestSignDocumentInternal(t *testing.T) {
	key, cert, err := generateTestKeys()
	if err != nil {
		t.Fatalf("Failed to generate test keys: %v", err)
	}

	xmlDoc := `<factura id="comprobante"><info>test content</info></factura>`
	
	// Test signing with SHA1 (default for SRI)
	signedXML, err := signDocumentInternal(xmlDoc, key, cert, "factura", SHA1)
	if err != nil {
		t.Fatalf("signDocumentInternal failed: %v", err)
	}

	// Basic Structure Verification
	if !strings.Contains(signedXML, "<?xml") {
		t.Error("Missing XML header")
	}
	if !strings.Contains(signedXML, "<ds:Signature") {
		t.Error("Missing Signature element")
	}
	if !strings.Contains(signedXML, "Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"") {
		t.Error("Wrong signature algorithm for SHA1")
	}
	
	// Verify XML Validity
	var doc interface{}
	if err := xml.Unmarshal([]byte(signedXML), &doc); err != nil {
		t.Errorf("Generated XML is invalid: %v", err)
	}
}

func TestBuildSignedProperties(t *testing.T) {
	_, cert, err := generateTestKeys()
	if err != nil {
		t.Fatal(err)
	}

	sp := buildSignedProperties("sp-1", "doc-1", cert, AlgorithmDigestSHA1)
	if sp == nil {
		t.Fatal("buildSignedProperties returned nil")
	}

	// Verify Structure
	if sp.Tag != "SignedProperties" {
		t.Errorf("Expected SignedProperties, got %s", sp.Tag)
	}
	if sp.SelectAttrValue("Id", "") != "sp-1" {
		t.Error("Id mismatch")
	}

	// Verify Namespace prefixes (etsi)
	// etree tags include prefix if set
	// Our builder creates "etsi:SignedProperties"
	// Let's verify internal nodes
	if sp.FindElement("etsi:SignedSignatureProperties") == nil {
		t.Error("Missing etsi:SignedSignatureProperties")
	}
	
	// Verify CertDigest
	certEl := sp.FindElement("./etsi:SignedSignatureProperties/etsi:SigningCertificate/etsi:Cert/etsi:CertDigest")
	if certEl == nil {
		t.Error("Missing CertDigest structure")
	} else {
		digest := certEl.FindElement("ds:DigestValue")
		if digest == nil || digest.Text() == "" {
			t.Error("Missing or empty DigestValue")
		}
		// Verify SHA1 hash matches
		expectedHash := libcrypto.GetCertHash(cert)
		if digest.Text() != expectedHash {
			t.Errorf("Cert hash mismatch. Got %s, want %s", digest.Text(), expectedHash)
		}
	}
}

func TestBuildKeyInfo(t *testing.T) {
	key, cert, err := generateTestKeys()
	if err != nil {
		t.Fatal(err)
	}

	ki := buildKeyInfo("ki-1", key, cert)
	
	// Verify X509Data
	x509Data := ki.FindElement("ds:X509Data")
	if x509Data == nil {
		t.Fatal("Missing X509Data")
	}
	certContent := x509Data.FindElement("ds:X509Certificate")
	if certContent == nil || certContent.Text() == "" {
		t.Error("Missing certificate content in KeyInfo")
	}

	// Verify KeyValue (Modulus/Exponent)
	rsaKv := ki.FindElement("ds:KeyValue/ds:RSAKeyValue")
	if rsaKv == nil {
		t.Error("Missing RSAKeyValue")
	} else {
		if rsaKv.FindElement("ds:Modulus") == nil {
			t.Error("Missing Modulus")
		}
		if rsaKv.FindElement("ds:Exponent") == nil {
			t.Error("Missing Exponent")
		}
	}
}

func TestBuildSignedInfo(t *testing.T) {
	si := buildSignedInfo("si-1", AlgorithmSignatureSHA1, AlgorithmDigestSHA1, "ref-doc", "ref-sp", "ref-ki", "hashDoc", "hashSP", "hashKI")

	// Verify Algorithms
	c14n := si.FindElement("ds:CanonicalizationMethod")
	if c14n == nil || c14n.SelectAttrValue("Algorithm", "") != AlgorithmC14N {
		t.Error("Wrong CanonicalizationMethod")
	}

	sigMethod := si.FindElement("ds:SignatureMethod")
	if sigMethod == nil || sigMethod.SelectAttrValue("Algorithm", "") != AlgorithmSignatureSHA1 {
		t.Error("Wrong SignatureMethod")
	}

	// Verify References (should be 3: Doc, Props, KeyInfo)
	refs := si.SelectElements("ds:Reference")
	if len(refs) != 3 {
		t.Errorf("Expected 3 references, got %d", len(refs))
	}

	// Verify Document Reference Transforms
	docRef := si.FindElement("ds:Reference[@URI='#comprobante']")
	if docRef == nil {
		t.Fatal("Document reference not found")
	}
	
	transforms := docRef.FindElement("ds:Transforms")
	if transforms == nil {
		t.Error("Missing Transforms for document")
	} else {
		tList := transforms.SelectElements("ds:Transform")
		if len(tList) != 1 { // Updated requirement: Only Enveloped
			t.Errorf("Expected 1 transform (Enveloped), got %d", len(tList))
		}
		if tList[0].SelectAttrValue("Algorithm", "") != AlgorithmTransform {
			t.Error("Expected Enveloped Signature transform")
		}
	}
}

func TestBuildFinalSignature(t *testing.T) {
	validXML := []byte("<root></root>")
	sig := buildFinalSignature("sig-1", "val-1", "obj-1", validXML, "valB64", validXML, validXML)

	if sig.Tag != "Signature" { // "ds:Signature" when serialized
		t.Error("Root tag should be Signature")
	}
	
	// Check namespace placement (Critical for SRI)
	// xmlns:etsi should NOT be in Signature root, but in Object
	if sig.SelectAttr("xmlns:etsi") != nil {
		t.Error("xmlns:etsi should NOT be in Signature root")
	}

	obj := sig.FindElement("ds:Object")
	if obj == nil {
		t.Fatal("Missing Object")
	}
	
	qp := obj.FindElement("etsi:QualifyingProperties")
	if qp == nil {
		t.Fatal("Missing QualifyingProperties")
	}
	
	if qp.SelectAttrValue("xmlns:etsi", "") != XadesNamespace {
		t.Error("QualifyingProperties missing xmlns:etsi definition")
	}
}
