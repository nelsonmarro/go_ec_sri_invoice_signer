package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"software.sslmate.com/src/go-pkcs12"
)

// ParsePKCS12 parses a P12/PFX file and returns the private key and certificate.
func ParsePKCS12(data []byte, password string) (*rsa.PrivateKey, *x509.Certificate, error) {
	// crypto/pkcs12 Decode returns the first private key and certificate it finds.
	// This usually works for standard p12 files.
	// For specialized cases like "Banco Central", we rely on the standard library behavior
	// hoping it picks the correct one (usually the one associated with the cert).
	pv, cert, err := pkcs12.Decode(data, password)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode pkcs12: %w", err)
	}

	rsaKey, ok := pv.(*rsa.PrivateKey)
	if !ok {
		return nil, nil, errors.New("private key is not an RSA key")
	}

	return rsaKey, cert, nil
}

// SHA1 returns the base64 encoded SHA1 hash of the data.
func SHA1(data []byte) string {
	h := sha1.New()
	h.Write(data)
	sum := h.Sum(nil)
	return base64.StdEncoding.EncodeToString(sum)
}

// SHA256 returns the base64 encoded SHA256 hash of the data.
func SHA256(data []byte) string {
	h := sha256.New()
	h.Write(data)
	sum := h.Sum(nil)
	return base64.StdEncoding.EncodeToString(sum)
}

// Sign signs the data using RSA-SHA256 and returns the base64 encoded signature.
func Sign(data []byte, key *rsa.PrivateKey) (string, error) {
	h := sha256.New()
	h.Write(data)
	digest := h.Sum(nil)

	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(signature), nil
}

// GetPrivateKeyData extracts Modulus and Exponent from an RSA private key.
func GetPrivateKeyData(key *rsa.PrivateKey) (string, string) {
	modulus := base64.StdEncoding.EncodeToString(key.N.Bytes())
	// Exponent is usually int, need to convert to big endian bytes
	e := big.NewInt(int64(key.E))
	exponent := base64.StdEncoding.EncodeToString(e.Bytes())
	return modulus, exponent
}

// GetIssuerName returns the certificate issuer name as a string formatted for SRI.
func GetIssuerName(cert *x509.Certificate) string {
	// SRI expects no spaces after commas. Go's String() adds them.
	return strings.ReplaceAll(cert.Issuer.String(), ", ", ",")
}

// GetCertHash returns the base64 encoded SHA256 hash of the raw certificate.
func GetCertHash(cert *x509.Certificate) string {
	h := sha256.New()
	h.Write(cert.Raw)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// GetCertContent returns the base64 encoded raw certificate content.
func GetCertContent(cert *x509.Certificate) string {
	return base64.StdEncoding.EncodeToString(cert.Raw)
}
