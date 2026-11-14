// Package crypto proporciona funciones para manejar claves y certificados criptográficos.
package crypto

import (
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"math/big"

	"software.sslmate.com/src/go-pkcs12"
)

// ParsePKCS12 extracts the signing key and its certificate from a .p12/.pfx file.
//
// Files issued by Ecuadorian CAs usually carry the issuing chain as well, and
// not always with the signer's certificate first, so the certificate returned
// is the one whose public key matches the private key.
func ParsePKCS12(data []byte, password string) (*rsa.PrivateKey, *x509.Certificate, error) {
	pv, first, others, err := pkcs12.DecodeChain(data, password)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode pkcs12: %w", err)
	}
	rsaKey, ok := pv.(*rsa.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("private key is not an RSA key")
	}
	for _, cert := range append([]*x509.Certificate{first}, others...) {
		if pub, ok := cert.PublicKey.(*rsa.PublicKey); ok && pub.Equal(&rsaKey.PublicKey) {
			return rsaKey, cert, nil
		}
	}
	return nil, nil, fmt.Errorf("no certificate in the pkcs12 file matches its private key")
}

func SHA1(data []byte) string {
	h := sha1.New()
	h.Write(data)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func SHA256(data []byte) string {
	h := sha256.New()
	h.Write(data)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func GetPrivateKeyData(key *rsa.PrivateKey) (string, string) {
	modulus := base64.StdEncoding.EncodeToString(key.N.Bytes())
	e := big.NewInt(int64(key.E))
	exponent := base64.StdEncoding.EncodeToString(e.Bytes())
	return modulus, exponent
}

// GetIssuerName returns the issuer distinguished name in RFC 2253 form (most
// specific RDN first, comma-separated without spaces, special characters
// escaped), which is what xades:X509IssuerName carries.
func GetIssuerName(cert *x509.Certificate) string {
	return cert.Issuer.String()
}

func GetCertHash(cert *x509.Certificate) string {
	h := sha1.New() // Por defecto SRI usa SHA1 para el CertDigest en XAdES
	h.Write(cert.Raw)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func GetCertContent(cert *x509.Certificate) string {
	return base64.StdEncoding.EncodeToString(cert.Raw)
}
