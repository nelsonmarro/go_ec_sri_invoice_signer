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
	"strings"

	"software.sslmate.com/src/go-pkcs12"
)

func ParsePKCS12(data []byte, password string) (*rsa.PrivateKey, *x509.Certificate, error) {
	pv, cert, err := pkcs12.Decode(data, password)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode pkcs12: %w", err)
	}
	rsaKey, ok := pv.(*rsa.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("private key is not an RSA key")
	}
	return rsaKey, cert, nil
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

func GetIssuerName(cert *x509.Certificate) string {
	// El SRI espera el formato RFC 2253 (CN primero).
	// cert.Issuer.String() de Go suele devolverlo correctamente pero con espacios.
	// Eliminamos los espacios tras las comas para cumplir con la literalidad del SRI.
	return strings.ReplaceAll(cert.Issuer.String(), ", ", ",")
}

func GetCertHash(cert *x509.Certificate) string {
	h := sha1.New() // Por defecto SRI usa SHA1 para el CertDigest en XAdES
	h.Write(cert.Raw)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func GetCertContent(cert *x509.Certificate) string {
	return base64.StdEncoding.EncodeToString(cert.Raw)
}
