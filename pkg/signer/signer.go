// Package signer provides functions to sign electronic documents (Factura, Nota de Crédito, etc.)
// compliant with the Ecuadorian SRI (Servicio de Rentas Internas) specifications.
package signer

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"

	libcrypto "github.com/nelsonmarro/go_ec_sri_invoice_signer/pkg/crypto"
	dsig "github.com/russellhaering/goxmldsig"
)

// HashAlgorithm defines the digest algorithm to use for signing.
type HashAlgorithm int

const (
	SHA1 HashAlgorithm = iota
	SHA256
)

// SignOptions configuration for the signing process.
type SignOptions struct {
	Password  string
	Algorithm HashAlgorithm
}

// SRIKeyStore adapts the rsa.PrivateKey and Certificate for goxmldsig.
type SRIKeyStore struct {
	privateKey *rsa.PrivateKey
	cert       []byte
}

func (s *SRIKeyStore) GetKeyPair() (*rsa.PrivateKey, []byte, error) {
	return s.privateKey, s.cert, nil
}

// Public API Functions

func SignInvoice(xmlDoc string, p12Data []byte, options *SignOptions) (string, error) {
	return signDocument(xmlDoc, p12Data, "factura", options)
}

func SignCreditNote(xmlDoc string, p12Data []byte, options *SignOptions) (string, error) {
	return signDocument(xmlDoc, p12Data, "notaCredito", options)
}

func SignDebitNote(xmlDoc string, p12Data []byte, options *SignOptions) (string, error) {
	return signDocument(xmlDoc, p12Data, "notaDebito", options)
}

func SignDeliveryGuide(xmlDoc string, p12Data []byte, options *SignOptions) (string, error) {
	return signDocument(xmlDoc, p12Data, "guiaRemision", options)
}

func SignWithholdingCertificate(xmlDoc string, p12Data []byte, options *SignOptions) (string, error) {
	return signDocument(xmlDoc, p12Data, "comprobanteRetencion", options)
}

// Core Signing Logic

func signDocument(docXML string, p12Data []byte, rootTagName string, options *SignOptions) (string, error) {
	pwd, algo := parseOptions(options)
	key, cert, err := libcrypto.ParsePKCS12(p12Data, pwd)
	if err != nil {
		return "", fmt.Errorf("failed to parse PKCS#12 file: %w", err)
	}
	return signDocumentInternal(docXML, key, cert, rootTagName, algo)
}

// signDocumentInternal allows signing with already parsed keys (useful for testing without P12 files)
// This function is internal to the package but accessible by tests in the same package.
func signDocumentInternal(docXML string, key *rsa.PrivateKey, cert *x509.Certificate, rootTagName string, algo HashAlgorithm) (string, error) {
	// 1. Prepare Document (Clean & Parse)
	cleanXML := cleanXMLString(docXML)
	root, err := parseRootElement(cleanXML)
	if err != nil {
		return "", err
	}
	ensureRootID(root)

	// 2. Determine Algorithms
	digestURL, sigURL, cryptoHash, digestFn := getAlgorithmConfig(algo)

	// 3. Generate Unique IDs
	ids := generateXadesIDs()

	// 4. Calculate Document Hash
	// Strategy: Hash the clean bytes directly. This matches the SRI's behavior after "Enveloped Signature" transform.
	docHashB64 := digestFn([]byte(cleanXML))

	// 5. Instantiate Canonicalizer (Inclusive C14N 1.0)
	canon := dsig.MakeC14N10RecCanonicalizer()

	// 6. Construct XAdES Components

	// A. SignedProperties (etsi:SignedProperties)
	spEl := buildSignedProperties(ids.SignedProps, ids.DocRef, cert, digestURL)
	spCanonical, _ := canon.Canonicalize(spEl)
	spHashB64 := digestFn(spCanonical)

	// B. KeyInfo (ds:KeyInfo)
	kiEl := buildKeyInfo(ids.KeyInfo, key, cert)
	kiCanonical, _ := canon.Canonicalize(kiEl)
	kiHashB64 := digestFn(kiCanonical)

	// C. SignedInfo (ds:SignedInfo)
	siEl := buildSignedInfo(ids.SigInfo, sigURL, digestURL, ids.DocRef, ids.SignedProps, ids.KeyInfo, docHashB64, spHashB64, kiHashB64)
	siCanonical, _ := canon.Canonicalize(siEl)

	// 7. Sign the SignedInfo
	sigCtx := dsig.NewDefaultSigningContext(&SRIKeyStore{privateKey: key, cert: cert.Raw})
	sigCtx.Hash = cryptoHash
	signatureValue, err := sigCtx.SignString(string(siCanonical))
	if err != nil {
		return "", fmt.Errorf("crypto signing failed: %w", err)
	}
	sigValueB64 := base64.StdEncoding.EncodeToString(signatureValue)

	// 8. Assemble Final Signature
	signature := buildFinalSignature(ids.Signature, ids.SigValue, ids.Object, siCanonical, sigValueB64, kiCanonical, spCanonical)

	// 9. Inject Signature into Document
	return injectSignature(cleanXML, rootTagName, signature, canon)
}
