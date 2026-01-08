package signer

import (
	"encoding/xml"
	"os"
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
	if !strings.Contains(signedXml, "<ds:KeyInfo") {
		t.Error("expected KeyInfo tag")
	}
	if !strings.Contains(signedXml, "xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"") {
		t.Error("expected ds namespace")
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
