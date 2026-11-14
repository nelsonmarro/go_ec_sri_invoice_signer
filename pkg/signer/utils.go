package signer

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	"github.com/beevik/etree"
	libcrypto "github.com/nelsonmarro/go_ec_sri_invoice_signer/pkg/crypto"
)

// Helper Functions & Builders
func parseOptions(options *SignOptions) (string, HashAlgorithm) {
	if options == nil {
		return "", SHA1
	}
	return options.Password, options.Algorithm
}

func getAlgorithmConfig(algo HashAlgorithm) (string, string, crypto.Hash, func([]byte) string) {
	if algo == SHA256 {
		return AlgorithmDigestSHA256, AlgorithmSignatureSHA256, crypto.SHA256, libcrypto.SHA256
	}
	return AlgorithmDigestSHA1, AlgorithmSignatureSHA1, crypto.SHA1, libcrypto.SHA1
}

func cleanXMLString(xmlStr string) string {
	xmlStr = strings.TrimSpace(xmlStr)
	if idx := strings.Index(xmlStr, "?>"); idx != -1 {
		xmlStr = xmlStr[idx+2:]
	}
	return strings.TrimSpace(xmlStr)
}

func parseRootElement(xmlBytes string) (*etree.Element, error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes([]byte(xmlBytes)); err != nil {
		return nil, fmt.Errorf("failed to parse XML document: %w", err)
	}
	root := doc.Root()
	if root == nil {
		return nil, fmt.Errorf("failed to parse XML document: no root element")
	}
	return root, nil
}

// ensureRootID returns the value of the root's id attribute, adding the SRI
// default ("comprobante") when the document has none.
func ensureRootID(root *etree.Element) string {
	if attr := root.SelectAttr("id"); attr != nil {
		return attr.Value
	}
	root.CreateAttr("id", defaultRootID)
	return defaultRootID
}

type xadesIDs struct {
	Signature   string
	SigInfo     string
	SigValue    string
	KeyInfo     string
	Object      string
	SignedProps string
	DocRef      string
}

func generateXadesIDs() xadesIDs {
	return xadesIDs{
		Signature:   "Signature" + randomID(),
		SigInfo:     "Signature-SignedInfo" + randomID(),
		SigValue:    "SignatureValue" + randomID(),
		KeyInfo:     "Certificate" + randomID(),
		Object:      "Signature-Object" + randomID(),
		SignedProps: "Signature-SignedProperties" + randomID(),
		DocRef:      "Reference-ID-" + randomID(),
	}
}

func buildSignedProperties(id, docRefID string, cert *x509.Certificate, digestAlgo string) *etree.Element {
	spEl := etree.NewElement("etsi:SignedProperties")
	spEl.CreateAttr("Id", id)
	spEl.CreateAttr("xmlns:etsi", XadesNamespace)
	spEl.CreateAttr("xmlns:ds", DsNamespace)

	loc := time.FixedZone("UTC-5", -5*60*60)
	signingTime := nowFunc().In(loc).Format("2006-01-02T15:04:05-07:00")

	certHash := libcrypto.GetCertHash(cert)
	issuerName := libcrypto.GetIssuerName(cert)
	serialNumber := cert.SerialNumber.String()
	ssp := spEl.CreateElement("etsi:SignedSignatureProperties")
	ssp.CreateElement("etsi:SigningTime").SetText(signingTime)

	certEl := ssp.CreateElement("etsi:SigningCertificate").CreateElement("etsi:Cert")
	cd := certEl.CreateElement("etsi:CertDigest")
	cd.CreateElement("ds:DigestMethod").CreateAttr("Algorithm", digestAlgo)
	cd.CreateElement("ds:DigestValue").SetText(certHash)
	issue := certEl.CreateElement("etsi:IssuerSerial")
	issue.CreateElement("ds:X509IssuerName").SetText(issuerName)
	issue.CreateElement("ds:X509SerialNumber").SetText(serialNumber)

	sdop := spEl.CreateElement("etsi:SignedDataObjectProperties")
	dof := sdop.CreateElement("etsi:DataObjectFormat")
	dof.CreateAttr("ObjectReference", "#"+docRefID)
	dof.CreateElement("etsi:Description").SetText("contenido comprobante")
	dof.CreateElement("etsi:MimeType").SetText("text/xml")

	return spEl
}

func buildKeyInfo(id string, key *rsa.PrivateKey, cert *x509.Certificate) *etree.Element {
	kiEl := etree.NewElement("ds:KeyInfo")
	kiEl.CreateAttr("Id", id)
	kiEl.CreateAttr("xmlns:ds", DsNamespace)
	kiEl.CreateElement("ds:X509Data").CreateElement("ds:X509Certificate").SetText(libcrypto.GetCertContent(cert))

	modulus, exponent := libcrypto.GetPrivateKeyData(key)
	kv := kiEl.CreateElement("ds:KeyValue").CreateElement("ds:RSAKeyValue")
	kv.CreateElement("ds:Modulus").SetText(modulus)
	kv.CreateElement("ds:Exponent").SetText(exponent)
	return kiEl
}

func buildSignedInfo(id, sigAlgo, digestAlgo, docRefID, rootID, spRefID, kiRefID, docHash, spHash, kiHash string) *etree.Element {
	siEl := etree.NewElement("ds:SignedInfo")
	siEl.CreateAttr("Id", id)
	siEl.CreateAttr("xmlns:ds", DsNamespace)
	siEl.CreateElement("ds:CanonicalizationMethod").CreateAttr("Algorithm", AlgorithmC14N)
	siEl.CreateElement("ds:SignatureMethod").CreateAttr("Algorithm", sigAlgo)

	// Ref 1: SignedProperties
	refProps := siEl.CreateElement("ds:Reference")
	refProps.CreateAttr("Type", "http://uri.etsi.org/01903#SignedProperties")
	refProps.CreateAttr("URI", "#"+spRefID)
	refProps.CreateElement("ds:DigestMethod").CreateAttr("Algorithm", digestAlgo)
	refProps.CreateElement("ds:DigestValue").SetText(spHash)

	// Ref 2: KeyInfo
	refKI := siEl.CreateElement("ds:Reference")
	refKI.CreateAttr("URI", "#"+kiRefID)
	refKI.CreateElement("ds:DigestMethod").CreateAttr("Algorithm", digestAlgo)
	refKI.CreateElement("ds:DigestValue").SetText(kiHash)

	// Ref 3: Document
	refDoc := siEl.CreateElement("ds:Reference")
	refDoc.CreateAttr("Id", docRefID)
	refDoc.CreateAttr("URI", "#"+rootID)
	trans := refDoc.CreateElement("ds:Transforms")
	trans.CreateElement("ds:Transform").CreateAttr("Algorithm", AlgorithmTransform)
	// No explicit C14N transform: the verifier canonicalizes with the default
	// (inclusive C14N 1.0), which is the form the document digest is computed on.

	refDoc.CreateElement("ds:DigestMethod").CreateAttr("Algorithm", digestAlgo)
	refDoc.CreateElement("ds:DigestValue").SetText(docHash)

	return siEl
}

// buildSignature assembles ds:Signature without SignedInfo and SignatureValue,
// which depend on digests of the other parts. It also returns the
// SignedProperties and KeyInfo elements so they can be digested in place.
func buildSignature(ids xadesIDs, key *rsa.PrivateKey, cert *x509.Certificate, digestAlgo string) (signature, signedProps, keyInfo *etree.Element) {
	signature = etree.NewElement("ds:Signature")
	signature.CreateAttr("Id", ids.Signature)
	signature.CreateAttr("xmlns:ds", DsNamespace)
	// xmlns:etsi is declared on QualifyingProperties, not here: declaring it on
	// ds:Signature would put it in scope of SignedInfo and change its digest.

	keyInfo = buildKeyInfo(ids.KeyInfo, key, cert)
	signature.AddChild(keyInfo)

	obj := signature.CreateElement("ds:Object")
	obj.CreateAttr("Id", ids.Object)
	qp := obj.CreateElement("etsi:QualifyingProperties")
	qp.CreateAttr("xmlns:etsi", XadesNamespace)
	qp.CreateAttr("Target", "#"+ids.Signature)

	signedProps = buildSignedProperties(ids.SignedProps, ids.DocRef, cert, digestAlgo)
	qp.AddChild(signedProps)

	return signature, signedProps, keyInfo
}

// Test seams: the golden tests pin the clock and the ID source.
var (
	nowFunc    = time.Now
	selfVerify = Verify
	randomID   = func() string {
		b := make([]byte, 4)
		rand.Read(b)
		return fmt.Sprintf("%x", b)
	}
)
