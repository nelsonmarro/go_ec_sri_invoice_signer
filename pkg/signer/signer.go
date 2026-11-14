// Package signer provides functions to sign electronic documents (Factura, Nota de Crédito, etc.)
// compliant with the Ecuadorian SRI (Servicio de Rentas Internas) specifications.
package signer

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/beevik/etree"
	libcrypto "github.com/nelsonmarro/go_ec_sri_invoice_signer/pkg/crypto"
	dsig "github.com/russellhaering/goxmldsig"
)

// HashAlgorithm defines the digest algorithm to use for signing.
type HashAlgorithm int

const (
	SHA1 HashAlgorithm = iota
	SHA256
)

// Root element names of the SRI electronic documents.
const (
	RootInvoice                = "factura"
	RootCreditNote             = "notaCredito"
	RootDebitNote              = "notaDebito"
	RootDeliveryGuide          = "guiaRemision"
	RootWithholdingCertificate = "comprobanteRetencion"
	RootPurchaseSettlement     = "liquidacionCompra"
)

var (
	// ErrCertificateExpired is returned when the signing certificate's validity period has ended.
	ErrCertificateExpired = errors.New("signing certificate has expired")
	// ErrCertificateNotYetValid is returned when the signing certificate's validity period has not started.
	ErrCertificateNotYetValid = errors.New("signing certificate is not yet valid")
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

// Sign signs any SRI document whose root element is rootTagName (see the Root*
// constants) with the certificate and key stored in the PKCS#12 data.
//
// The returned document is serialized in canonical form (C14N 1.0), so it can
// differ from the input in insignificant ways (empty elements are written as
// start/end tag pairs, attributes are reordered, comments are dropped).
func Sign(xmlDoc string, p12Data []byte, rootTagName string, options *SignOptions) (string, error) {
	return signDocument(xmlDoc, p12Data, rootTagName, options)
}

func SignInvoice(xmlDoc string, p12Data []byte, options *SignOptions) (string, error) {
	return signDocument(xmlDoc, p12Data, RootInvoice, options)
}

func SignCreditNote(xmlDoc string, p12Data []byte, options *SignOptions) (string, error) {
	return signDocument(xmlDoc, p12Data, RootCreditNote, options)
}

func SignDebitNote(xmlDoc string, p12Data []byte, options *SignOptions) (string, error) {
	return signDocument(xmlDoc, p12Data, RootDebitNote, options)
}

func SignDeliveryGuide(xmlDoc string, p12Data []byte, options *SignOptions) (string, error) {
	return signDocument(xmlDoc, p12Data, RootDeliveryGuide, options)
}

func SignWithholdingCertificate(xmlDoc string, p12Data []byte, options *SignOptions) (string, error) {
	return signDocument(xmlDoc, p12Data, RootWithholdingCertificate, options)
}

func SignPurchaseSettlement(xmlDoc string, p12Data []byte, options *SignOptions) (string, error) {
	return signDocument(xmlDoc, p12Data, RootPurchaseSettlement, options)
}

// Core Signing Logic

func signDocument(docXML string, p12Data []byte, rootTagName string, options *SignOptions) (string, error) {
	pwd, algo := parseOptions(options)
	key, cert, err := libcrypto.ParsePKCS12(p12Data, pwd)
	if err != nil {
		return "", fmt.Errorf("failed to parse PKCS#12 file: %w", err)
	}
	if err := checkCertificateValidity(cert); err != nil {
		return "", err
	}
	return signDocumentInternal(docXML, key, cert, rootTagName, algo)
}

func checkCertificateValidity(cert *x509.Certificate) error {
	now := nowFunc()
	if now.After(cert.NotAfter) {
		return fmt.Errorf("%w on %s", ErrCertificateExpired, cert.NotAfter.Format("2006-01-02"))
	}
	if now.Before(cert.NotBefore) {
		return fmt.Errorf("%w until %s", ErrCertificateNotYetValid, cert.NotBefore.Format("2006-01-02"))
	}
	return nil
}

// signDocumentInternal allows signing with already parsed keys (useful for testing without P12 files)
// This function is internal to the package but accessible by tests in the same package.
func signDocumentInternal(docXML string, key *rsa.PrivateKey, cert *x509.Certificate, rootTagName string, algo HashAlgorithm) (string, error) {
	// 1. Prepare Document (Clean & Parse)
	root, err := parseRootElement(cleanXMLString(docXML))
	if err != nil {
		return "", err
	}
	if root.Tag != rootTagName {
		return "", fmt.Errorf("root element is <%s>, expected <%s>", root.Tag, rootTagName)
	}
	rootID := ensureRootID(root)

	// 2. Determine Algorithms
	digestURL, sigURL, cryptoHash, digestFn := getAlgorithmConfig(algo)

	// 3. Generate Unique IDs
	ids := generateXadesIDs()

	// 4. Calculate Document Hash
	// A verifier applies the enveloped-signature transform and then canonicalizes
	// the document, so the digest must cover the canonical form, never the raw
	// input bytes. The signature is not attached yet, which is exactly what the
	// enveloped-signature transform leaves behind.
	canon := dsig.MakeC14N10RecCanonicalizer()
	docCanonical, err := canon.Canonicalize(root)
	if err != nil {
		return "", fmt.Errorf("failed to canonicalize document: %w", err)
	}
	docHashB64 := digestFn(docCanonical)

	// 5. Attach the signature skeleton (KeyInfo + XAdES Object) to the document.
	// SignedProperties, KeyInfo and SignedInfo are canonicalized in place: inclusive
	// C14N renders every namespace in scope on the element, including the ones
	// declared on the document root, and that is what a verifier will digest.
	signature, spEl, kiEl := buildSignature(ids, key, cert, digestURL)
	root.AddChild(signature)

	spCanonical, err := canon.Canonicalize(spEl)
	if err != nil {
		return "", fmt.Errorf("failed to canonicalize SignedProperties: %w", err)
	}
	kiCanonical, err := canon.Canonicalize(kiEl)
	if err != nil {
		return "", fmt.Errorf("failed to canonicalize KeyInfo: %w", err)
	}

	// 6. SignedInfo (ds:SignedInfo)
	siEl := buildSignedInfo(ids.SigInfo, sigURL, digestURL, ids.DocRef, rootID, ids.SignedProps, ids.KeyInfo,
		docHashB64, digestFn(spCanonical), digestFn(kiCanonical))
	signature.InsertChildAt(0, siEl)
	siCanonical, err := canon.Canonicalize(siEl)
	if err != nil {
		return "", fmt.Errorf("failed to canonicalize SignedInfo: %w", err)
	}

	// 7. Sign the SignedInfo
	sigCtx := dsig.NewDefaultSigningContext(&SRIKeyStore{privateKey: key, cert: cert.Raw})
	sigCtx.Hash = cryptoHash
	signatureValue, err := sigCtx.SignString(string(siCanonical))
	if err != nil {
		return "", fmt.Errorf("crypto signing failed: %w", err)
	}
	svEl := etree.NewElement("ds:SignatureValue")
	svEl.CreateAttr("Id", ids.SigValue)
	svEl.SetText(base64.StdEncoding.EncodeToString(signatureValue))
	signature.InsertChildAt(1, svEl)

	// 8. Serialize the signed document in canonical form
	signedCanonical, err := canon.Canonicalize(root)
	if err != nil {
		return "", fmt.Errorf("failed to serialize signed document: %w", err)
	}
	signedXML := xmlHeader + string(signedCanonical)

	// 9. Self-check: never hand out a signature that does not verify
	if err := selfVerify(signedXML); err != nil {
		return "", fmt.Errorf("signed document failed self-verification: %w", err)
	}
	return signedXML, nil
}
