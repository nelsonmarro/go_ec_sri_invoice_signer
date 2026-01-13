// Package signer provides functions to sign various types of electronic documents
package signer

import (
	"crypto/rand"
	"encoding/xml"
	"fmt"
	"strings"
	"time"

	"github.com/nelsonmarro/go_ec_sri_invoice_signer/pkg/c14n"
	"github.com/nelsonmarro/go_ec_sri_invoice_signer/pkg/crypto"
	"github.com/nelsonmarro/go_ec_sri_invoice_signer/pkg/types"
)

type SignOptions struct {
	Password string
}

// SignInvoice signs a Factura (Invoice) XML document.
func SignInvoice(xmlDoc string, p12Data []byte, options *SignOptions) (string, error) {
	return signDocument(xmlDoc, p12Data, "factura", options)
}

// SignCreditNote signs a Nota de Crédito (Credit Note) XML document.
func SignCreditNote(xmlDoc string, p12Data []byte, options *SignOptions) (string, error) {
	return signDocument(xmlDoc, p12Data, "notaCredito", options)
}

// SignDebitNote signs a Nota de Débito (Debit Note) XML document.
func SignDebitNote(xmlDoc string, p12Data []byte, options *SignOptions) (string, error) {
	return signDocument(xmlDoc, p12Data, "notaDebito", options)
}

// SignDeliveryGuide signs a Guía de Remisión (Delivery Guide) XML document.
func SignDeliveryGuide(xmlDoc string, p12Data []byte, options *SignOptions) (string, error) {
	return signDocument(xmlDoc, p12Data, "guiaRemision", options)
}

// SignWithholdingCertificate signs a Comprobante de Retención (Withholding Certificate) XML document.
func SignWithholdingCertificate(xmlDoc string, p12Data []byte, options *SignOptions) (string, error) {
	return signDocument(xmlDoc, p12Data, "comprobanteRetencion", options)
}

func signDocument(docXML string, p12Data []byte, rootTagName string, options *SignOptions) (string, error) {
	pwd := ""
	if options != nil {
		pwd = options.Password
	}

	key, cert, err := crypto.ParsePKCS12(p12Data, pwd)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrParsingP12, err)
	}

	// 1. Canonicalize Document
	docCanonical, err := c14n.Canonicalize([]byte(docXML))
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrCanonicalization, err)
	}
	docHash := crypto.SHA256(docCanonical)

	// IDs
	docTagId := "comprobante"
	// We use random IDs. Node uses uuid. We'll use a simple random string generator.
	docTagRefId := fmt.Sprintf("DocumentRef-%s", randomID())
	keyInfoTagId := fmt.Sprintf("Certificate-%s", randomID())
	keyInfoRefTagId := fmt.Sprintf("CertificateRef-%s", randomID())
	signedInfoTagId := fmt.Sprintf("SignedInfo-%s", randomID())
	signedPropertiesRefTagId := fmt.Sprintf("SignedPropertiesRef-%s", randomID())
	signedPropertiesTagId := fmt.Sprintf("SignedProperties-%s", randomID())
	signatureTagId := fmt.Sprintf("Signature-%s", randomID())
	signatureObjectTagId := fmt.Sprintf("SignatureObject-%s", randomID())
	signatureValueTagId := fmt.Sprintf("SignatureValue-%s", randomID())

	// Certificate Data
	modulus, exponent := crypto.GetPrivateKeyData(key)
	certContent := crypto.GetCertContent(cert)
	certHash := crypto.GetCertHash(cert)
	issuerName := crypto.GetIssuerName(cert)
	serialNumber := cert.SerialNumber.String()

	// 2. Build KeyInfo
	keyInfo := types.KeyInfo{
		ID: keyInfoTagId,
		X509Data: types.X509Data{
			X509Certificate: certContent,
		},
		KeyValue: types.KeyValue{
			RSAKeyValue: types.RSAKeyValue{
				Modulus:  modulus,
				Exponent: exponent,
			},
		},
	}

	// KeyInfo Hash
	keyInfoBytes, _ := xml.Marshal(keyInfo)
	// Hack: inject xmlns:ds if missing for C14N isolated
	keyInfoWithNs := ensureNamespace(keyInfoBytes, "ds", types.DsNamespace)
	keyInfoCanonical, err := c14n.Canonicalize(keyInfoWithNs)
	if err != nil {
		return "", fmt.Errorf("%w (KeyInfo): %v", ErrCanonicalization, err)
	}
	keyInfoHash := crypto.SHA256(keyInfoCanonical)

	// 3. Build SignedProperties
	signingTime := time.Now().Format("2006-01-02T15:04:05-07:00") // ISO8601 with offset
	signedProperties := types.SignedProperties{
		ID: signedPropertiesTagId,
		SignedSignatureProperties: types.SignedSignatureProperties{
			SigningTime: signingTime,
			SigningCertificate: types.SigningCertificate{
				Cert: types.Cert{
					CertDigest: types.CertDigest{
						DigestMethod: types.AlgorithmMethod{Algorithm: types.AlgorithmDigest},
						DigestValue:  certHash,
					},
					IssuerSerial: types.IssuerSerial{
						X509IssuerName:   issuerName,
						X509SerialNumber: serialNumber,
					},
				},
			},
		},
		SignedDataObjectProperties: types.SignedDataObjectProperties{
			DataObjectFormat: types.DataObjectFormat{
				ObjectReference: "#" + docTagRefId,
				Description:     "Firma digital",
				MimeType:        "text/xml",
				Encoding:        "UTF-8",
			},
		},
	}

	// SignedProperties Hash
	signedPropsBytes, _ := xml.Marshal(signedProperties)
	// Inject namespaces xades and ds
	signedPropsWithNs := ensureNamespace(signedPropsBytes, "xades", types.XadesNamespace)
	signedPropsWithNs = ensureNamespace(signedPropsWithNs, "ds", types.DsNamespace)
	signedPropsCanonical, err := c14n.Canonicalize(signedPropsWithNs)
	if err != nil {
		return "", fmt.Errorf("%w (SignedProperties): %v", ErrCanonicalization, err)
	}
	signedPropsHash := crypto.SHA256(signedPropsCanonical)

	// 4. Build SignedInfo
	signedInfo := types.SignedInfo{
		ID:                     signedInfoTagId,
		CanonicalizationMethod: types.AlgorithmMethod{Algorithm: types.AlgorithmC14N},
		SignatureMethod:        types.AlgorithmMethod{Algorithm: types.AlgorithmSignature},
		References: []types.Reference{
			{
				ID:  docTagRefId,
				URI: "#" + docTagId,
				Transforms: &types.Transforms{
					Transform: []types.AlgorithmMethod{
						{Algorithm: types.AlgorithmTransform},
						{Algorithm: types.AlgorithmC14N},
					},
				},
				DigestMethod: types.AlgorithmMethod{Algorithm: types.AlgorithmDigest},
				DigestValue:  docHash,
			},
			{
				ID:           signedPropertiesRefTagId,
				Type:         types.TypeSignedProperties,
				URI:          "#" + signedPropertiesTagId,
				DigestMethod: types.AlgorithmMethod{Algorithm: types.AlgorithmDigest},
				DigestValue:  signedPropsHash,
			},
			{
				ID:           keyInfoRefTagId,
				URI:          "#" + keyInfoTagId,
				DigestMethod: types.AlgorithmMethod{Algorithm: types.AlgorithmDigest},
				DigestValue:  keyInfoHash,
			},
		},
	}

	// SignedInfo Signing
	signedInfoBytes, _ := xml.Marshal(signedInfo)
	signedInfoWithNs := ensureNamespace(signedInfoBytes, "ds", types.DsNamespace)
	signedInfoCanonical, err := c14n.Canonicalize(signedInfoWithNs)
	if err != nil {
		return "", fmt.Errorf("%w (SignedInfo): %v", ErrCanonicalization, err)
	}
	signatureValue, err := crypto.Sign(signedInfoCanonical, key)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrSigning, err)
	}

	// 5. Build Signature
	signature := types.Signature{
		XmlnsDs:    types.DsNamespace,
		ID:         signatureTagId,
		SignedInfo: signedInfo,
		SignatureValue: types.SignatureValue{
			ID:    signatureValueTagId,
			Value: signatureValue,
		},
		KeyInfo: keyInfo,
		Object: types.Object{
			ID: signatureObjectTagId,
			QualifyingProperties: types.QualifyingProperties{
				XmlnsXades:       types.XadesNamespace,
				Target:           "#" + signatureTagId,
				SignedProperties: signedProperties,
			},
		},
	}

	// Marshal final signature
	signatureBytes, err := xml.Marshal(signature)
	if err != nil {
		return "", fmt.Errorf("failed to marshal signature: %w", err)
	}

	// Optimization: Since SRI's Reference doesn't have C14N transform,
	// we must ensure the XML we send is IDENTICAL to what we hashed.
	// We replace the marshaled fragments with their canonicalized versions.
	finalSignatureStr := string(signatureBytes)
	
	// Replace KeyInfo with canonicalized version
	// Note: keyInfoCanonical already has xmlns:ds injected
	oldKeyInfo, _ := xml.Marshal(keyInfo)
	finalSignatureStr = strings.Replace(finalSignatureStr, string(oldKeyInfo), string(keyInfoCanonical), 1)

	// Replace SignedProperties with canonicalized version
	oldSignedProps, _ := xml.Marshal(signedProperties)
	finalSignatureStr = strings.Replace(finalSignatureStr, string(oldSignedProps), string(signedPropsCanonical), 1)

	// 6. Insert into Document
	// Find </rootTagName> and insert before it
	closingTag := fmt.Sprintf("</%s>", rootTagName)
	if !strings.Contains(docXML, closingTag) {
		return "", fmt.Errorf("%w: %s", ErrMissingClosingTag, closingTag)
	}

	// IMPORTANT: We must use the canonicalized document body to ensure the hash matches
	// But we should keep the XML declaration if it was there.
	header := ""
	if strings.HasPrefix(strings.TrimSpace(docXML), "<?xml") {
		endDecl := strings.Index(docXML, "?>")
		if endDecl != -1 {
			header = docXML[:endDecl+2] + "\n"
		}
	}

	finalXml := header + strings.Replace(string(docCanonical), closingTag, finalSignatureStr+closingTag, 1)

	return finalXml, nil
}

func randomID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Entropy source failure is fatal for signature generation
		panic(fmt.Errorf("failed to generate random ID: %w", err))
	}
	return fmt.Sprintf("%x", b)
}

// ensureNamespace attempts to add xmlns:prefix="uri" to the root element if not present.
// This is a rough hack for C14N context.
func ensureNamespace(xmlData []byte, prefix, uri string) []byte {
	// Check if xmlns:prefix is already there
	s := string(xmlData)
	nsAttr := fmt.Sprintf("xmlns:%s", prefix)
	if strings.Contains(s, nsAttr) {
		return xmlData
	}

	// Find first space after tag name or end of tag name
	// <TagName ...
	// <ds:TagName ...
	firstTagEnd := strings.IndexByte(s, '>')
	if firstTagEnd == -1 {
		return xmlData
	}

	firstSpace := strings.IndexByte(s, ' ')
	if firstSpace == -1 || firstSpace > firstTagEnd {
		// No attributes, insert at end of tag name
		// But tag name might be <ds:Tag>
		// Insert before '>'
		return []byte(s[:firstTagEnd] + fmt.Sprintf(" %s=\"%s\"", nsAttr, uri) + s[firstTagEnd:])
	}

	// Insert after tag name (at first space)
	return []byte(s[:firstSpace] + fmt.Sprintf(" %s=\"%s\"", nsAttr, uri) + s[firstSpace:])
}
