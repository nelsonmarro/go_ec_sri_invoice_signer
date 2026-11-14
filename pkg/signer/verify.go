package signer

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// ErrInvalidSignature is returned by Verify when a digest or the signature
// value does not match the document.
var ErrInvalidSignature = errors.New("invalid signature")

// Verify checks the enveloped XAdES-BES signature of an SRI document the way a
// standard XMLDSig validator does: it recomputes the digest of every
// ds:Reference and verifies the RSA signature over the canonical ds:SignedInfo
// with the public key of the embedded certificate.
//
// It does not validate the certificate itself (trust chain, revocation or
// validity period); the SRI does that when it receives the document.
func Verify(signedXML string) error {
	root, err := parseRootElement(cleanXMLString(signedXML))
	if err != nil {
		return err
	}
	signature := childByTag(root, "Signature")
	if signature == nil {
		return fmt.Errorf("%w: document has no ds:Signature", ErrInvalidSignature)
	}
	signedInfo := childByTag(signature, "SignedInfo")
	if signedInfo == nil {
		return fmt.Errorf("%w: missing ds:SignedInfo", ErrInvalidSignature)
	}

	canon := dsig.MakeC14N10RecCanonicalizer()

	references := childrenByTag(signedInfo, "Reference")
	if len(references) == 0 {
		return fmt.Errorf("%w: ds:SignedInfo has no references", ErrInvalidSignature)
	}
	coversDocument := false
	for _, ref := range references {
		target, err := verifyReference(root, signature, ref, canon)
		if err != nil {
			return err
		}
		if target == root {
			coversDocument = true
		}
	}
	if !coversDocument {
		return fmt.Errorf("%w: no reference covers the document root", ErrInvalidSignature)
	}

	return verifySignatureValue(signature, signedInfo, canon)
}

// verifyReference recomputes the digest of one ds:Reference and returns the
// element it points to.
func verifyReference(root, signature, ref *etree.Element, canon dsig.Canonicalizer) (*etree.Element, error) {
	uri := ref.SelectAttrValue("URI", "")
	if !strings.HasPrefix(uri, "#") || len(uri) < 2 {
		return nil, fmt.Errorf("%w: unsupported reference URI %q", ErrInvalidSignature, uri)
	}
	target := findByID(root, uri[1:])
	if target == nil {
		return nil, fmt.Errorf("%w: reference %q points to no element", ErrInvalidSignature, uri)
	}

	subject := target
	if transforms := childByTag(ref, "Transforms"); transforms != nil {
		for _, tr := range childrenByTag(transforms, "Transform") {
			switch algo := tr.SelectAttrValue("Algorithm", ""); algo {
			case AlgorithmTransform:
				if target != root {
					return nil, fmt.Errorf("%w: enveloped-signature transform on %q, which is not the document root", ErrInvalidSignature, uri)
				}
				subject = withoutChild(root, signature)
			case AlgorithmC14N:
				// Inclusive C14N 1.0 is what the digest input is serialized with anyway.
			default:
				return nil, fmt.Errorf("%w: unsupported transform %q", ErrInvalidSignature, algo)
			}
		}
	}

	canonical, err := canon.Canonicalize(subject)
	if err != nil {
		return nil, fmt.Errorf("failed to canonicalize reference %q: %w", uri, err)
	}
	hash, err := hashForDigestMethod(childAttr(ref, "DigestMethod", "Algorithm"))
	if err != nil {
		return nil, err
	}
	want := compactText(childByTag(ref, "DigestValue"))
	if got := base64.StdEncoding.EncodeToString(sum(hash, canonical)); got != want {
		return nil, fmt.Errorf("%w: digest mismatch for reference %q", ErrInvalidSignature, uri)
	}
	return target, nil
}

func verifySignatureValue(signature, signedInfo *etree.Element, canon dsig.Canonicalizer) error {
	var hash crypto.Hash
	switch algo := childAttr(signedInfo, "SignatureMethod", "Algorithm"); algo {
	case AlgorithmSignatureSHA1:
		hash = crypto.SHA1
	case AlgorithmSignatureSHA256:
		hash = crypto.SHA256
	default:
		return fmt.Errorf("%w: unsupported signature method %q", ErrInvalidSignature, algo)
	}
	if method := childAttr(signedInfo, "CanonicalizationMethod", "Algorithm"); method != AlgorithmC14N {
		return fmt.Errorf("%w: unsupported canonicalization method %q", ErrInvalidSignature, method)
	}

	publicKey, err := embeddedPublicKey(signature)
	if err != nil {
		return err
	}
	sigValue, err := base64.StdEncoding.DecodeString(compactText(childByTag(signature, "SignatureValue")))
	if err != nil {
		return fmt.Errorf("%w: ds:SignatureValue is not valid base64", ErrInvalidSignature)
	}
	siCanonical, err := canon.Canonicalize(signedInfo)
	if err != nil {
		return fmt.Errorf("failed to canonicalize SignedInfo: %w", err)
	}
	if err := rsa.VerifyPKCS1v15(publicKey, hash, sum(hash, siCanonical), sigValue); err != nil {
		return fmt.Errorf("%w: signature value does not match ds:SignedInfo", ErrInvalidSignature)
	}
	return nil
}

func embeddedPublicKey(signature *etree.Element) (*rsa.PublicKey, error) {
	var certEl *etree.Element
	if keyInfo := childByTag(signature, "KeyInfo"); keyInfo != nil {
		if x509Data := childByTag(keyInfo, "X509Data"); x509Data != nil {
			certEl = childByTag(x509Data, "X509Certificate")
		}
	}
	if certEl == nil {
		return nil, fmt.Errorf("%w: missing ds:X509Certificate", ErrInvalidSignature)
	}
	der, err := base64.StdEncoding.DecodeString(compactText(certEl))
	if err != nil {
		return nil, fmt.Errorf("%w: ds:X509Certificate is not valid base64", ErrInvalidSignature)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot parse embedded certificate: %v", ErrInvalidSignature, err)
	}
	publicKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: embedded certificate does not hold an RSA key", ErrInvalidSignature)
	}
	return publicKey, nil
}

func hashForDigestMethod(algo string) (crypto.Hash, error) {
	switch algo {
	case AlgorithmDigestSHA1:
		return crypto.SHA1, nil
	case AlgorithmDigestSHA256:
		return crypto.SHA256, nil
	}
	return 0, fmt.Errorf("%w: unsupported digest method %q", ErrInvalidSignature, algo)
}

func sum(hash crypto.Hash, data []byte) []byte {
	if hash == crypto.SHA256 {
		s := sha256.Sum256(data)
		return s[:]
	}
	s := sha1.Sum(data)
	return s[:]
}

// withoutChild returns a copy of parent that lacks the given child element.
func withoutChild(parent, child *etree.Element) *etree.Element {
	idx := child.Index()
	cp := parent.Copy()
	cp.RemoveChildAt(idx)
	return cp
}

// findByID returns the first element, in document order, carrying an ID
// attribute (id, Id or ID) with the given value.
func findByID(el *etree.Element, id string) *etree.Element {
	for _, attr := range el.Attr {
		if attr.Space == "" && strings.EqualFold(attr.Key, "id") && attr.Value == id {
			return el
		}
	}
	for _, child := range el.ChildElements() {
		if found := findByID(child, id); found != nil {
			return found
		}
	}
	return nil
}

// childByTag and childrenByTag match on the local name, whatever the prefix.
func childByTag(el *etree.Element, tag string) *etree.Element {
	for _, child := range el.ChildElements() {
		if child.Tag == tag {
			return child
		}
	}
	return nil
}

func childrenByTag(el *etree.Element, tag string) []*etree.Element {
	var out []*etree.Element
	for _, child := range el.ChildElements() {
		if child.Tag == tag {
			out = append(out, child)
		}
	}
	return out
}

func childAttr(el *etree.Element, tag, attr string) string {
	if child := childByTag(el, tag); child != nil {
		return child.SelectAttrValue(attr, "")
	}
	return ""
}

// compactText returns the element text without any whitespace (base64 values
// may be wrapped across lines).
func compactText(el *etree.Element) string {
	if el == nil {
		return ""
	}
	return strings.Join(strings.Fields(el.Text()), "")
}
