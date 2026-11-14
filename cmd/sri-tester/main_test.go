package main

import (
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
)

var testNow = time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)

const testAccessKey = "1411202607179000000000110010010000000011234567811"

func renderForTest(t *testing.T, docType string) *etree.Element {
	t.Helper()
	xmlStr, err := renderTemplate(docType, "1790000000001", testAccessKey, testNow)
	if err != nil {
		t.Fatalf("renderTemplate(%s): %v", docType, err)
	}
	if strings.Contains(xmlStr, "{{") {
		t.Errorf("%s: unreplaced placeholder left in the document", docType)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromString(xmlStr); err != nil {
		t.Fatalf("%s: rendered template is not well-formed: %v", docType, err)
	}
	return doc.Root()
}

func text(t *testing.T, root *etree.Element, path string) string {
	t.Helper()
	el := root.FindElement(path)
	if el == nil {
		t.Fatalf("missing element %s", path)
	}
	return el.Text()
}

func TestEveryTemplateRenders(t *testing.T) {
	for docType, code := range sriDocCodes {
		root := renderForTest(t, docType)
		if root.Tag != docType {
			t.Errorf("%s: root element is <%s>", docType, root.Tag)
		}
		if got := text(t, root, "./infoTributaria/codDoc"); got != code {
			t.Errorf("%s: codDoc = %s, want %s", docType, got, code)
		}
		if got := text(t, root, "./infoTributaria/claveAcceso"); got != testAccessKey {
			t.Errorf("%s: claveAcceso = %s", docType, got)
		}
	}
}

func TestRenderTemplateRejectsUnknownType(t *testing.T) {
	if _, err := renderTemplate("proforma", "1790000000001", testAccessKey, testNow); err == nil {
		t.Error("want an error for an unknown document type")
	}
}

// The withholding certificate must use the ATS format (version 2.0.0), where
// the withholdings live inside the supporting document, with the rates of
// Resolución NAC-DGERCGC26-00000009 (in force since 2026-03-01).
func TestWithholdingTemplateIsATSVersion2(t *testing.T) {
	root := renderForTest(t, "comprobanteRetencion")

	if v := root.SelectAttrValue("version", ""); v != "2.0.0" {
		t.Errorf("version = %q, want 2.0.0", v)
	}
	if root.FindElement("./impuestos") != nil {
		t.Error("the flat <impuestos> block belongs to version 1.0.0")
	}
	if got := text(t, root, "./infoCompRetencion/parteRel"); got != "NO" {
		t.Errorf("parteRel = %q", got)
	}
	if got := text(t, root, "./infoCompRetencion/periodoFiscal"); got != "11/2026" {
		t.Errorf("periodoFiscal = %q, want the emission month 11/2026", got)
	}

	doc := root.FindElement("./docsSustento/docSustento")
	if doc == nil {
		t.Fatal("missing docsSustento/docSustento")
	}
	if got := text(t, doc, "./fechaEmisionDocSustento"); got != "14/11/2026" {
		t.Errorf("fechaEmisionDocSustento = %q", got)
	}
	for path, want := range map[string]string{
		"./totalSinImpuestos": "100.00",
		"./importeTotal":      "115.00",
		"./impuestosDocSustento/impuestoDocSustento/baseImponible": "100.00",
		"./impuestosDocSustento/impuestoDocSustento/tarifa":        "15",
		"./impuestosDocSustento/impuestoDocSustento/valorImpuesto": "15.00",
		"./pagos/pago/total": "115.00",
	} {
		if got := text(t, doc, path); got != want {
			t.Errorf("%s = %q, want %q", path, got, want)
		}
	}

	type line struct{ codigo, codigoRetencion, base, porcentaje, valor string }
	want := []line{
		{"1", "312", "100.00", "2", "2.00"}, // renta: bienes muebles 2 %
		{"2", "1", "15.00", "30", "4.50"},   // IVA: 30 % en bienes
	}
	rets := doc.FindElements("./retenciones/retencion")
	if len(rets) != len(want) {
		t.Fatalf("got %d retenciones, want %d", len(rets), len(want))
	}
	for i, w := range want {
		got := line{
			text(t, rets[i], "./codigo"), text(t, rets[i], "./codigoRetencion"), text(t, rets[i], "./baseImponible"),
			text(t, rets[i], "./porcentajeRetener"), text(t, rets[i], "./valorRetenido"),
		}
		if got != w {
			t.Errorf("retencion %d = %+v, want %+v", i, got, w)
		}
	}
}
