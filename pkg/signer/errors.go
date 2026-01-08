package signer

import "errors"

var (
	ErrParsingP12          = errors.New("failed to parse PKCS#12 file")
	ErrCanonicalization    = errors.New("failed to canonicalize XML")
	ErrSigning             = errors.New("failed to sign document")
	ErrInvalidDocument     = errors.New("invalid XML document for signing")
	ErrMissingClosingTag   = errors.New("closing root tag not found in document")
)
