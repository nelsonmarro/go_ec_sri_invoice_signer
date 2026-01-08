package c14n

import (
	"bytes"
	"encoding/xml"
	"fmt"

	c14nlib "github.com/ucarion/c14n"
)

// Canonicalize transforms the XML data into its canonical form (C14N 1.0 Exclusive usually, or inclusive).
// The Node code implements a custom "simple" C14N.
// We will try to use standard C14N.
func Canonicalize(data []byte) ([]byte, error) {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	out, err := c14nlib.Canonicalize(decoder)
	if err != nil {
		return nil, fmt.Errorf("c14n error: %w", err)
	}
	return out, nil
}
