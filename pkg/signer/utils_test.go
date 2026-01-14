package signer

import (
	"crypto"
	"strings"
	"testing"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

func TestCleanXMLString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "XML with declaration",
			input:    `<?xml version="1.0" encoding="UTF-8"?><root>test</root>`,
			expected: "<root>test</root>",
		},
		{
			name:     "XML with declaration and spaces",
			input:    `  <?xml version="1.0" ?>  <root>test</root>  `,
			expected: "<root>test</root>",
		},
		{
			name:     "XML without declaration",
			input:    `<root>test</root>`,
			expected: "<root>test</root>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cleanXMLString(tt.input)
			if got != tt.expected {
				t.Errorf("cleanXMLString() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestGetAlgorithmConfig(t *testing.T) {
	// Test SHA1 (Default)
	dURL, sURL, h, _ := getAlgorithmConfig(SHA1)
	if dURL != AlgorithmDigestSHA1 {
		t.Errorf("SHA1 digest URL mismatch")
	}
	if sURL != AlgorithmSignatureSHA1 {
		t.Errorf("SHA1 signature URL mismatch")
	}
	if h != crypto.SHA1 {
		t.Errorf("SHA1 crypto hash mismatch")
	}

	// Test SHA256
	dURL, sURL, h, _ = getAlgorithmConfig(SHA256)
	if dURL != AlgorithmDigestSHA256 {
		t.Errorf("SHA256 digest URL mismatch")
	}
	if sURL != AlgorithmSignatureSHA256 {
		t.Errorf("SHA256 signature URL mismatch")
	}
	if h != crypto.SHA256 {
		t.Errorf("SHA256 crypto hash mismatch")
	}
}

func TestParseOptions(t *testing.T) {
	// Nil options
	pwd, algo := parseOptions(nil)
	if pwd != "" || algo != SHA1 {
		t.Error("parseOptions(nil) should return defaults")
	}

	// Custom options
	opts := &SignOptions{Password: "secret", Algorithm: SHA256}
	pwd, algo = parseOptions(opts)
	if pwd != "secret" || algo != SHA256 {
		t.Error("parseOptions should return configured values")
	}
}

func TestEnsureRootID(t *testing.T) {
	// Case 1: No ID
	doc := etree.NewDocument()
	root := doc.CreateElement("factura")
	ensureRootID(root)
	if root.SelectAttrValue("id", "") != "comprobante" {
		t.Error("ensureRootID failed to add id attribute")
	}

	// Case 2: Existing ID
	root2 := doc.CreateElement("factura")
	root2.CreateAttr("id", "existing")
	ensureRootID(root2)
	if root2.SelectAttrValue("id", "") != "existing" {
		t.Error("ensureRootID should not overwrite existing id")
	}
}

func TestParseRootElement(t *testing.T) {
	// Valid XML
	_, err := parseRootElement("<root></root>")
	if err != nil {
		t.Errorf("parseRootElement failed on valid XML: %v", err)
	}

	// Invalid XML
	_, err = parseRootElement("<root>")
	if err == nil {
		t.Error("parseRootElement should fail on invalid XML")
	}
}

func TestRandomID(t *testing.T) {
	id1 := randomID()
	id2 := randomID()
	if id1 == id2 {
		t.Error("randomID should generate unique IDs")
	}
	if len(id1) == 0 {
		t.Error("randomID should not be empty")
	}
}

func TestInjectSignature(t *testing.T) {
	cleanXML := `<factura id="comprobante"><info>test</info></factura>`
	canon := dsig.MakeC14N10RecCanonicalizer()
	sig := etree.NewElement("ds:Signature")
	sig.CreateAttr("Id", "sig123")

	signed, err := injectSignature(cleanXML, "factura", sig, canon)
	if err != nil {
		t.Fatalf("injectSignature failed: %v", err)
	}

	if !strings.Contains(signed, "<?xml") {
		t.Error("result should have XML header")
	}
	if !strings.Contains(signed, "standalone=\"no\"") {
		t.Error("result should have standalone=no")
	}
	if !strings.Contains(signed, "<ds:Signature Id=\"sig123\"") {
		t.Error("signature not injected correctly")
	}
	// Check position: inside root, likely at end
	if !strings.HasSuffix(strings.TrimSpace(signed), "</factura>") {
		t.Error("signature should be inside root element")
	}
}