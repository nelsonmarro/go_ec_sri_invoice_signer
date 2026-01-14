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
	dsig "github.com/russellhaering/goxmldsig"
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
	return doc.Root(), nil
}

func ensureRootID(root *etree.Element) {
	if root.SelectAttr("id") == nil {
		root.CreateAttr("id", "comprobante")
	}
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
	signingTime := time.Now().In(loc).Format("2006-01-02T15:04:05-07:00")

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

func buildSignedInfo(id, sigAlgo, digestAlgo, docRefID, spRefID, kiRefID, docHash, spHash, kiHash string) *etree.Element {
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
	refDoc.CreateAttr("URI", "#comprobante")
	trans := refDoc.CreateElement("ds:Transforms")
	trans.CreateElement("ds:Transform").CreateAttr("Algorithm", AlgorithmTransform)
	// C14N removed here to match document hashing strategy

	refDoc.CreateElement("ds:DigestMethod").CreateAttr("Algorithm", digestAlgo)
	refDoc.CreateElement("ds:DigestValue").SetText(docHash)

	return siEl
}

func buildFinalSignature(sigID, sigValueID, objID string, siCanonical []byte, sigValueB64 string, kiCanonical, spCanonical []byte) *etree.Element {
	signature := etree.NewElement("ds:Signature")
	signature.CreateAttr("Id", sigID)
	signature.CreateAttr("xmlns:ds", DsNamespace)
	// xmlns:etsi removed from root to keep SignedInfo clean

	// SignedInfo
	siDoc := etree.NewDocument()
	_ = siDoc.ReadFromBytes(siCanonical)
	signature.AddChild(siDoc.Root())

	// SignatureValue
	svEl := signature.CreateElement("ds:SignatureValue")
	svEl.CreateAttr("Id", sigValueID)
	svEl.SetText(sigValueB64)

	// KeyInfo
	kiDoc := etree.NewDocument()
	_ = kiDoc.ReadFromBytes(kiCanonical)
	signature.AddChild(kiDoc.Root())

	// Object (XAdES)
	obj := signature.CreateElement("ds:Object")
	obj.CreateAttr("Id", objID)
	qp := obj.CreateElement("etsi:QualifyingProperties")
	qp.CreateAttr("xmlns:etsi", XadesNamespace)
	qp.CreateAttr("Target", "#"+sigID)

	spDoc := etree.NewDocument()
	_ = spDoc.ReadFromBytes(spCanonical)
	qp.AddChild(spDoc.Root())

	obj.AddChild(qp)

	return signature
}

func injectSignature(cleanXML, rootTagName string, signature *etree.Element, canon dsig.Canonicalizer) (string, error) {
	sigBytes, _ := canon.Canonicalize(signature)
	finalSignatureStr := string(sigBytes)

	closingTag := fmt.Sprintf("</%s>", rootTagName)
	idx := strings.LastIndex(cleanXML, closingTag)
	if idx == -1 {
		return "", fmt.Errorf("closing tag %s not found", closingTag)
	}

	header := `<?xml version="1.0" encoding="UTF-8" standalone="no"?>` + "\n"
	return header + cleanXML[:idx] + finalSignatureStr + cleanXML[idx:], nil
}

func randomID() string {
	b := make([]byte, 4)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}
