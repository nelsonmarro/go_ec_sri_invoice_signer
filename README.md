# Go EC SRI Invoice Signer

A Go package for signing electronic invoices for the Ecuadorian SRI
(Servicio de Rentas Internas), ported from the Node.js [ec-sri-invoice-signer](https://github.com/bryancalisto/ec-sri-invoice-signer)

This library implements XAdES-BES signatures required by the SRI.

## Features

- Parse PKCS#12 (.p12) files to extract private keys and certificates.
- Canonicalize XML (C14N).
- Generate XAdES-BES signatures.
- Support for:
  - Invoices (Factura)
  - Credit Notes (Nota de Crédito)
  - Debit Notes (Nota de Débito)
  - Delivery Guides (Guía de Remisión)
  - Withholding Certificates (Comprobante de Retención)

## Installation

```bash
go get github.com/nelsonmarro/go_ec_sri_invoice_signer
```

## Usage

```go
package main

import (
 "fmt"
 "os"

 "github.com/nelsonmarro/go_ec_sri_invoice_signer/pkg/signer"
)

func main() {
 xmlContent := `... your xml ...`
 p12Bytes, _ := os.ReadFile("signature.p12")
 password := "your-password"

 signedXml, err := signer.SignInvoice(xmlContent, p12Bytes, &signer.SignOptions{
  Password: password,
 })
 if err != nil
  panic(err)
 }

 fmt.Println(signedXml)
}
```

## Structure

- `pkg/signer`: Main entry point for signing functions.
- `pkg/types`: XAdES XML structure definitions.
- `pkg/crypto`: Cryptographic helpers (PKCS12, SHA1, RSA).
- `pkg/c14n`: XML Canonicalization wrapper.

## License

MIT
