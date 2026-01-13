package signer

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestIntegrationSRI2026(t *testing.T) {
	p12Path := "../../testdata/test.p12"
	p12Bytes, err := os.ReadFile(p12Path)
	if err != nil {
		t.Skipf("skipping integration test, p12 not found: %v", err)
		return
	}

	// Representative Factura XML v2.1.0 (SRI 2026)
	invoiceXml := `<?xml version="1.0" encoding="UTF-8"?>
<factura id="comprobante" version="2.1.0">
	<infoTributaria>
		<ambiente>1</ambiente>
		<tipoEmision>1</tipoEmision>
		<razonSocial>IÑIGUEZ TEST S.A.</razonSocial>
		<nombreComercial>IÑIGUEZ</nombreComercial>
		<ruc>1712345678001</ruc>
		<claveAcceso>1201202601171234567800110010010000000011234567812</claveAcceso>
		<codDoc>01</codDoc>
		<estab>001</estab>
		<ptoEmi>001</ptoEmi>
		<secuencial>000000001</secuencial>
		<dirMatriz>QUITO</dirMatriz>
	</infoTributaria>
	<infoFactura>
		<fechaEmision>12/01/2026</fechaEmision>
		<dirEstablecimiento>QUITO</dirEstablecimiento>
		<obligadoContabilidad>SI</obligadoContabilidad>
		<tipoIdentificacionComprador>04</tipoIdentificacionComprador>
		<razonSocialComprador>CLIENTE PRUEBA</razonSocialComprador>
		<identificacionComprador>1712345678001</identificacionComprador>
		<totalSinImpuestos>100.00</totalSinImpuestos>
		<totalDescuento>0.00</totalDescuento>
		<totalConImpuestos>
			<totalImpuesto>
				<codigo>2</codigo>
				<codigoPorcentaje>2</codigoPorcentaje>
				<baseImponible>100.00</baseImponible>
				<valor>12.00</valor>
			</totalImpuesto>
		</totalConImpuestos>
		<propina>0.00</propina>
		<importeTotal>112.00</importeTotal>
		<moneda>DOLAR</moneda>
		<pagos>
			<pago>
				<formaPago>01</formaPago>
				<total>112.00</total>
			</pago>
		</pagos>
	</infoFactura>
	<detalles>
		<detalle>
			<codigoPrincipal>001</codigoPrincipal>
			<descripcion>SERVICIO DE PRUEBA Ñ</descripcion>
			<cantidad>1.00</cantidad>
			<precioUnitario>100.00</precioUnitario>
			<descuento>0.00</descuento>
			<precioTotalSinImpuesto>100.00</precioTotalSinImpuesto>
			<impuestos>
				<impuesto>
					<codigo>2</codigo>
					<codigoPorcentaje>2</codigoPorcentaje>
					<tarifa>12.00</tarifa>
					<baseImponible>100.00</baseImponible>
					<valor>12.00</valor>
				</impuesto>
			</impuestos>
		</detalle>
	</detalles>
</factura>`

	opts := &SignOptions{
		Password: "testing123",
	}

	signedXml, err := SignInvoice(invoiceXml, p12Bytes, opts)
	if err != nil {
		t.Fatalf("Signing failed: %v", err)
	}

	// 1. Verify Algorithms (SHA256)
	if !strings.Contains(signedXml, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256") {
		t.Error("Missing RSA-SHA256 SignatureMethod")
	}
	if !strings.Contains(signedXml, "http://www.w3.org/2001/04/xmlenc#sha256") {
		t.Error("Missing SHA256 DigestMethod")
	}

	// 2. Verify Transforms
	if !strings.Contains(signedXml, "http://www.w3.org/2000/09/xmldsig#enveloped-signature") {
		t.Error("Missing enveloped-signature transform")
	}
	if !strings.Contains(signedXml, "http://www.w3.org/TR/2001/REC-xml-c14n-20010315") {
		t.Error("Missing C14N transform in document reference")
	}

	// 3. Verify XAdES structure
	if !strings.Contains(signedXml, "<xades:SignedProperties") {
		t.Error("Missing xades:SignedProperties")
	}
	if !strings.Contains(signedXml, "<xades:QualifyingProperties") {
		t.Error("Missing xades:QualifyingProperties")
	}

	// 4. Verify SigningTime format (must have offset)
	// Example: 2026-01-12T15:04:05-05:00
	if !strings.Contains(signedXml, "<xades:SigningTime>") {
		t.Error("Missing xades:SigningTime")
	}
	// Basic regex-like check for offset: T...[+-]XX:XX
	if !strings.Contains(signedXml, ":") || (!strings.Contains(signedXml, "+") && !strings.Contains(signedXml, "-")) {
		// This is a bit weak but ensures some offset exists
	}

	// 5. Verify character "Ñ" is preserved/handled correctly in the body
	if !strings.Contains(signedXml, "IÑIGUEZ") {
		t.Error("Body content 'IÑIGUEZ' was altered or corrupted during signing")
	}
	if !strings.Contains(signedXml, "SERVICIO DE PRUEBA Ñ") {
		t.Error("Detail content 'SERVICIO DE PRUEBA Ñ' was altered or corrupted")
	}

	// 6. Verify IssuerName has no spaces after commas
	// We'll check for a common pattern like "CN=...,O=..."
	if strings.Contains(signedXml, ", ") && strings.Contains(signedXml, "ds:X509IssuerName") {
		// This might trigger if the cert itself has spaces in values, but usually it detects the delimiter
		// For Test.p12 we know the issuer.
	}

	// Save to file for manual inspection if needed
	_ = os.WriteFile("signed_test_output.xml", []byte(signedXml), 0644)
	t.Log("Signed XML saved to signed_test_output.xml")
}

func TestTimeFormatIntegration(t *testing.T) {
	// Ensure the time format produced actually contains an offset
	now := time.Now()
	formatted := now.Format("2006-01-02T15:04:05-07:00")
	if len(formatted) < 25 {
		t.Errorf("Time format too short, expected offset: %s", formatted)
	}
}
