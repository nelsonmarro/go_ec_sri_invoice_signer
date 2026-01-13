// Package types contains the XML structures for XML Digital Signatures (XMLDSig) and XAdES signatures.
package types

import "encoding/xml"

const (
	DsNamespace          = "http://www.w3.org/2000/09/xmldsig#"
	XadesNamespace       = "http://uri.etsi.org/01903/v1.3.2#"
	AlgorithmC14N        = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
	AlgorithmDigest      = "http://www.w3.org/2001/04/xmlenc#sha256"
	AlgorithmSignature   = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	AlgorithmTransform   = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
	TypeSignedProperties = "http://uri.etsi.org/01903#SignedProperties"
)

// DS Types

type KeyInfo struct {
	XMLName  xml.Name `xml:"ds:KeyInfo"`
	ID       string   `xml:"Id,attr"`
	X509Data X509Data `xml:"ds:X509Data"`
	KeyValue KeyValue `xml:"ds:KeyValue"`
}

type X509Data struct {
	XMLName         xml.Name `xml:"ds:X509Data"`
	X509Certificate string   `xml:"ds:X509Certificate"`
}

type KeyValue struct {
	XMLName     xml.Name    `xml:"ds:KeyValue"`
	RSAKeyValue RSAKeyValue `xml:"ds:RSAKeyValue"`
}

type RSAKeyValue struct {
	XMLName  xml.Name `xml:"ds:RSAKeyValue"`
	Modulus  string   `xml:"ds:Modulus"`
	Exponent string   `xml:"ds:Exponent"`
}

type SignedInfo struct {
	XMLName                xml.Name        `xml:"ds:SignedInfo"`
	ID                     string          `xml:"Id,attr"`
	CanonicalizationMethod AlgorithmMethod `xml:"ds:CanonicalizationMethod"`
	SignatureMethod        AlgorithmMethod `xml:"ds:SignatureMethod"`
	References             []Reference     `xml:"ds:Reference"`
}

type AlgorithmMethod struct {
	Algorithm string `xml:"Algorithm,attr"`
}

type Reference struct {
	ID           string          `xml:"Id,attr"`
	URI          string          `xml:"URI,attr"`
	Type         string          `xml:"Type,attr,omitempty"`
	Transforms   *Transforms     `xml:"ds:Transforms,omitempty"`
	DigestMethod AlgorithmMethod `xml:"ds:DigestMethod"`
	DigestValue  string          `xml:"ds:DigestValue"`
}

type Transforms struct {
	Transform []AlgorithmMethod `xml:"ds:Transform"`
}

type Signature struct {
	XMLName        xml.Name       `xml:"ds:Signature"`
	XmlnsDs        string         `xml:"xmlns:ds,attr"`
	XmlnsXades     string         `xml:"xmlns:xades,attr,omitempty"`
	ID             string         `xml:"Id,attr"`
	SignedInfo     SignedInfo     `xml:"ds:SignedInfo"`
	SignatureValue SignatureValue `xml:"ds:SignatureValue"`
	KeyInfo        KeyInfo        `xml:"ds:KeyInfo"`
	Object         Object         `xml:"ds:Object"`
}

type SignatureValue struct {
	XMLName xml.Name `xml:"ds:SignatureValue"`
	ID      string   `xml:"Id,attr"`
	Value   string   `xml:",chardata"`
}

type Object struct {
	XMLName              xml.Name             `xml:"ds:Object"`
	ID                   string               `xml:"Id,attr"`
	QualifyingProperties QualifyingProperties `xml:"xades:QualifyingProperties"`
}

// XAdES Types

type QualifyingProperties struct {
	XMLName          xml.Name         `xml:"xades:QualifyingProperties"`
	XmlnsXades       string           `xml:"xmlns:xades,attr"`
	Target           string           `xml:"Target,attr"`
	SignedProperties SignedProperties `xml:"xades:SignedProperties"`
}

type SignedProperties struct {
	XMLName                    xml.Name                   `xml:"xades:SignedProperties"`
	ID                         string                     `xml:"Id,attr"`
	SignedSignatureProperties  SignedSignatureProperties  `xml:"xades:SignedSignatureProperties"`
	SignedDataObjectProperties SignedDataObjectProperties `xml:"xades:SignedDataObjectProperties"`
}

type SignedSignatureProperties struct {
	XMLName            xml.Name           `xml:"xades:SignedSignatureProperties"`
	SigningTime        string             `xml:"xades:SigningTime"`
	SigningCertificate SigningCertificate `xml:"xades:SigningCertificate"`
}

type SigningCertificate struct {
	XMLName xml.Name `xml:"xades:SigningCertificate"`
	Cert    Cert     `xml:"xades:Cert"`
}

type Cert struct {
	XMLName      xml.Name     `xml:"xades:Cert"`
	CertDigest   CertDigest   `xml:"xades:CertDigest"`
	IssuerSerial IssuerSerial `xml:"xades:IssuerSerial"`
}

type CertDigest struct {
	XMLName      xml.Name        `xml:"xades:CertDigest"`
	DigestMethod AlgorithmMethod `xml:"ds:DigestMethod"`
	DigestValue  string          `xml:"ds:DigestValue"`
}

type IssuerSerial struct {
	XMLName          xml.Name `xml:"xades:IssuerSerial"`
	X509IssuerName   string   `xml:"ds:X509IssuerName"`
	X509SerialNumber string   `xml:"ds:X509SerialNumber"`
}

type SignedDataObjectProperties struct {
	XMLName          xml.Name         `xml:"xades:SignedDataObjectProperties"`
	DataObjectFormat DataObjectFormat `xml:"xades:DataObjectFormat"`
}

type DataObjectFormat struct {
	XMLName         xml.Name `xml:"xades:DataObjectFormat"`
	ObjectReference string   `xml:"ObjectReference,attr"`
	Description     string   `xml:"xades:Description"`
	MimeType        string   `xml:"xades:MimeType"`
	Encoding        string   `xml:"xades:Encoding"`
}