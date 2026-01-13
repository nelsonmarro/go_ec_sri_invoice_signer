package signer

import (
	"encoding/xml"
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestSignInvoice(t *testing.T) {
	p12Path := "../../testdata/test.p12"
	p12Bytes, err := os.ReadFile(p12Path)
	if err != nil {
		t.Skipf("skipping signer test, p12 not found: %v", err)
		return
	}

	invoiceXml := `<factura id="comprobante">
    <infoTributaria>
        <ambiente>1</ambiente>
        <tipoEmision>1</tipoEmision>
        <razonSocial>Test</razonSocial>
    </infoTributaria>
</factura>`

	opts := &SignOptions{
		Password: "testing123",
	}

	signedXml, err := SignInvoice(invoiceXml, p12Bytes, opts)
	if err != nil {
		t.Fatalf("SignInvoice failed: %v", err)
	}

	if !strings.Contains(signedXml, "<ds:Signature") {
		t.Error("expected Signature tag")
	}
	if !strings.Contains(signedXml, "xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"") {
		t.Error("expected ds namespace")
	}
	
	// SRI 2026 Checks:
	// 1. SHA1 Algorithm (Back to SHA1 for better compatibility as requested)
	if !strings.Contains(signedXml, "http://www.w3.org/2000/09/xmldsig#rsa-sha1") {
		t.Error("expected SHA1 signature method")
	}
	if !strings.Contains(signedXml, "http://www.w3.org/2000/09/xmldsig#sha1") {
		t.Error("expected SHA1 digest method")
	}

	// 2. Flattening (no spaces between root level tags)
	if strings.Contains(signedXml, ">\n    <infoTributaria>") {
		t.Error("expected flattened XML (no newlines/indentation between tags)")
	}

	// 3. Timezone in SigningTime
	// Look for pattern like 2026-01-13T11:01:52-05:00
	re := regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2}`)
	if !re.MatchString(signedXml) {
		t.Error("expected SigningTime with timezone offset")
	}
	
	// Basic XML validity check
	var doc interface{}
	if err := xml.Unmarshal([]byte(signedXml), &doc); err != nil {
		t.Errorf("signed XML is not valid XML: %v", err)
	}
}

func TestSignCreditNote(t *testing.T) {
	p12Path := "../../testdata/test.p12"
	p12Bytes, err := os.ReadFile(p12Path)
	if err != nil {
		t.Skip("no p12")
		return
	}

	xmlDoc := `<notaCredito id="comprobante"><infoTributaria></infoTributaria></notaCredito>`
	
	signed, err := SignCreditNote(xmlDoc, p12Bytes, &SignOptions{Password: "testing123"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(signed, "Signature") {
		t.Error("missing signature")
	}
}
