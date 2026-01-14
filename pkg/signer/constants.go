package signer

const (
	DsNamespace    = "http://www.w3.org/2000/09/xmldsig#"
	XadesNamespace = "http://uri.etsi.org/01903/v1.3.2#"
	
	// Algorithms
	AlgorithmC14N            = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
	AlgorithmDigestSHA1      = "http://www.w3.org/2000/09/xmldsig#sha1"
	AlgorithmSignatureSHA1   = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
	AlgorithmDigestSHA256    = "http://www.w3.org/2001/04/xmlenc#sha256"
	AlgorithmSignatureSHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	AlgorithmTransform       = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
)
