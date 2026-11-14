package signer

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// xmlsec1Verify checks a signed document with xmlsec1, an XMLDSig implementation
// that shares no code with this package. It plays the role of the SRI validator.
func xmlsec1Verify(t *testing.T, signedXML, rootTag string) {
	t.Helper()
	bin, err := exec.LookPath("xmlsec1")
	if err != nil {
		t.Skip("xmlsec1 not installed")
	}
	path := filepath.Join(t.TempDir(), "signed.xml")
	if err := os.WriteFile(path, []byte(signedXML), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bin, "--verify",
		"--id-attr:id", rootTag,
		"--id-attr:Id", XadesNamespace+":SignedProperties",
		"--trusted-pem", writeTestCertPEM(t),
		"--enabled-key-data", "x509,rsa",
		path).CombinedOutput()
	if err != nil {
		t.Errorf("xmlsec1 rejected the signature: %v\n%s", err, out)
	}
}

// Inputs a consumer can legitimately produce but that are not byte-identical to
// their own canonical form. v1.0.0 hashed the raw bytes and signed all of these
// into documents that a standard verifier rejects.
var nonCanonicalInputs = []struct {
	name, rootTag, xml string
}{
	{"self-closing empty element", "factura",
		`<factura id="comprobante" version="1.1.0"><info>x</info><campoAdicional/></factura>`},
	{"attributes out of canonical order", "factura",
		`<factura version="1.1.0" id="comprobante"><info>x</info></factura>`},
	{"namespace declared on the root", "factura",
		`<factura xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" id="comprobante" version="1.1.0"><info>x</info></factura>`},
	{"default namespace on the root", "factura",
		`<factura xmlns="urn:example:sri" id="comprobante" version="1.1.0"><info>x</info></factura>`},
	{"missing root id", "factura",
		`<factura version="1.1.0"><info>x</info></factura>`},
	{"root id other than comprobante", "factura",
		`<factura id="doc-1" version="1.1.0"><info>x</info></factura>`},
	{"CRLF line endings", "factura",
		"<factura id=\"comprobante\" version=\"1.1.0\">\r\n  <info>x</info>\r\n</factura>"},
	{"character references and quotes", "factura",
		`<factura id='comprobante' version="1.1.0"><info>A &#38; B &gt; C &quot;D&quot;</info></factura>`},
	{"CDATA section", "factura",
		`<factura id="comprobante" version="1.1.0"><info><![CDATA[A & B]]></info></factura>`},
	{"comment inside the document", "factura",
		`<factura id="comprobante" version="1.1.0"><!-- nota --><info>x</info></factura>`},
	{"retention certificate", "comprobanteRetencion",
		`<comprobanteRetencion id="comprobante" version="2.0.0"><docsSustento><docSustento/></docsSustento></comprobanteRetencion>`},
}

func TestSignedDocumentsVerifyWithXmlsec1(t *testing.T) {
	key, cert := loadTestKeyPair(t)
	for _, algo := range []HashAlgorithm{SHA1, SHA256} {
		for _, tc := range nonCanonicalInputs {
			name := tc.name + "/sha1"
			if algo == SHA256 {
				name = tc.name + "/sha256"
			}
			t.Run(name, func(t *testing.T) {
				signed, err := signDocumentInternal(tc.xml, key, cert, tc.rootTag, algo)
				if err != nil {
					t.Fatalf("sign: %v", err)
				}
				xmlsec1Verify(t, signed, tc.rootTag)
			})
		}
	}
}
