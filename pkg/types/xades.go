// Package types contains the XML structures for XML Digital Signatures (XMLDSig) and XAdES signatures.
package types

import "encoding/xml"

const (
	DsNamespace          = "http://www.w3.org/2000/09/xmldsig#"
	EtsiNamespace        = "http://uri.etsi.org/01903/v1.3.2#"
	AlgorithmC14N        = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
	AlgorithmDigest      = "http://www.w3.org/2000/09/xmldsig#sha1"
	AlgorithmSignature   = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
	AlgorithmTransform   = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
	TypeSignedProperties = "http://uri.etsi.org/01903#SignedProperties"
)

// DS Types

type KeyInfo struct {
	XMLName  xml.Name `xml:"ds:KeyInfo"`
	ID       string   `xml:"Id,attr"`
	X509Data X509Data
	KeyValue KeyValue
}

type X509Data struct {
	XMLName         xml.Name `xml:"ds:X509Data"`
	X509Certificate string   `xml:"ds:X509Certificate"`
}

type KeyValue struct {
	XMLName     xml.Name `xml:"ds:KeyValue"`
	RSAKeyValue RSAKeyValue
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
	XMLName        xml.Name `xml:"ds:Signature"`
	XmlnsDs        string   `xml:"xmlns:ds,attr"`
	XmlnsEtsi      string   `xml:"xmlns:etsi,attr,omitempty"` 
	ID             string   `xml:"Id,attr"`
	SignedInfo     SignedInfo
	SignatureValue SignatureValue
	KeyInfo        KeyInfo
	Object         Object
}

type SignatureValue struct {
	XMLName xml.Name `xml:"ds:SignatureValue"`
	ID      string   `xml:"Id,attr"`
	Value   string   `xml:",chardata"`
}

type Object struct {
	XMLName              xml.Name `xml:"ds:Object"`
	ID                   string   `xml:"Id,attr"`
	QualifyingProperties QualifyingProperties
}

// XAdES Types (Using 'etsi' prefix to match reference library)

type QualifyingProperties struct {
	XMLName          xml.Name `xml:"etsi:QualifyingProperties"`
	XmlnsEtsi        string   `xml:"xmlns:etsi,attr,omitempty"` // explicit ns if needed here
	Target           string   `xml:"Target,attr"`
	SignedProperties SignedProperties
}

type SignedProperties struct {
	XMLName                    xml.Name `xml:"etsi:SignedProperties"`
	ID                         string   `xml:"Id,attr"`
	SignedSignatureProperties  SignedSignatureProperties
	SignedDataObjectProperties SignedDataObjectProperties
}

type SignedSignatureProperties struct {
	XMLName            xml.Name `xml:"etsi:SignedSignatureProperties"`
	SigningTime        string   `xml:"etsi:SigningTime"`
	SigningCertificate SigningCertificate
}

type SigningCertificate struct {
	XMLName xml.Name `xml:"etsi:SigningCertificate"`
	Cert    Cert
}

type Cert struct {
	XMLName      xml.Name `xml:"etsi:Cert"`
	CertDigest   CertDigest
	IssuerSerial IssuerSerial
}

type CertDigest struct {
	XMLName      xml.Name        `xml:"etsi:CertDigest"`
	DigestMethod AlgorithmMethod `xml:"ds:DigestMethod"`
	DigestValue  string          `xml:"ds:DigestValue"`
}

type IssuerSerial struct {
	XMLName          xml.Name `xml:"etsi:IssuerSerial"`
	X509IssuerName   string   `xml:"ds:X509IssuerName"`
	X509SerialNumber string   `xml:"ds:X509SerialNumber"`
}

type SignedDataObjectProperties struct {
	XMLName          xml.Name `xml:"etsi:SignedDataObjectProperties"`
	DataObjectFormat DataObjectFormat
}

type DataObjectFormat struct {
	XMLName         xml.Name `xml:"etsi:DataObjectFormat"`
	ObjectReference string   `xml:"ObjectReference,attr"`
	Description     string   `xml:"etsi:Description"`
	MimeType        string   `xml:"etsi:MimeType"`
	Encoding        string   `xml:"etsi:Encoding"`
}
