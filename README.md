# 🇪🇨 Go EC SRI Invoice Signer

[![Go Reference](https://pkg.go.dev/badge/github.com/nelsonmarro/go_ec_sri_invoice_signer.svg)](https://pkg.go.dev/github.com/nelsonmarro/go_ec_sri_invoice_signer)
[![Go Report Card](https://goreportcard.com/badge/github.com/nelsonmarro/go_ec_sri_invoice_signer)](https://goreportcard.com/report/github.com/nelsonmarro/go_ec_sri_invoice_signer)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A robust, pure Go implementation for signing electronic documents according to the **Ecuadorian SRI (Servicio de Rentas Internas)** standards. This library is a Go port of the original Node.js implementation [ec-sri-invoice-signer](https://github.com/bryancalisto/ec-sri-invoice-signer) by Bryan Calisto.

---

## 🚀 Features

- **XAdES-BES Native**: Implements the specific signature structure required by SRI (including `QualifyingProperties` and `SignedProperties`).
- **Complete Document Support**:
  - 🧾 `Factura` (Invoice)
  - 📉 `Nota de Crédito` (Credit Note)
  - 📈 `Nota de Débito` (Debit Note)
  - 🚛 `Guía de Remisión` (Delivery Guide)
  - 💰 `Comprobante de Retención` (Withholding Certificate)
- **Robust Security**: Uses `software.sslmate.com/src/go-pkcs12` for reliable PKCS#12 parsing.
- **Pure Go**: No CGO dependencies, making it easy to cross-compile for any platform.

---

## 📦 Installation

```bash
go get github.com/nelsonmarro/go_ec_sri_invoice_signer
```

---

## 🛠 Usage

### Basic Example (Signing an Invoice)

```go
package main

import (
 "fmt"
 "os"

 "github.com/nelsonmarro/go_ec_sri_invoice_signer/pkg/signer"
)

func main() {
 // 1. Load your XML document (must be a valid SRI XML string)
 xmlContent := `<?xml version="1.0" encoding="UTF-8"?><factura id="comprobante">...</factura>`

 // 2. Load your signature file (.p12 or .pfx)
 p12Bytes, err := os.ReadFile("firma_electronica.p12")
 if err != nil {
  panic(err)
 }

 // 3. Sign the document
 signedXML, err := signer.SignInvoice(xmlContent, p12Bytes, &signer.SignOptions{
  Password: "your_password",
 })
 if err != nil {
  fmt.Printf("Error signing document: %v\n", err)
  return
 }

 // 4. Use the signed XML (e.g., send to SRI web service)
 fmt.Println(signedXML)
}
```

---

## 🏗 Architectural Decisions

This library was designed with specific constraints to ensure compatibility with SRI's legacy systems:

1. **PKCS#12 Library**: We use `software.sslmate.com/src/go-pkcs12` instead of the standard `x/crypto/pkcs12` to provide better support for various P12 encryption algorithms used by Ecuadorian certification authorities (like SecurityData, Banco Central, etc.).
2. **Canonicalization (C14N)**: Uses `github.com/ucarion/c14n` to ensure that the XML signature remains valid even after transmission.
3. **Id Generation**: Generates random unique IDs for each signature element (`Signature`, `SignedInfo`, `KeyInfo`, etc.) to prevent collisions in systems processing multiple documents.
4. **Error Handling**: Provides descriptive custom errors (e.g., `ErrParsingP12`, `ErrMissingClosingTag`) to help developers quickly identify integration issues.

---

## 📂 Project Structure

- `pkg/signer`: Public API. Use this to sign your documents.
- `pkg/crypto`: Internal helpers for RSA-SHA1 signing and P12 parsing.
- `pkg/c14n`: XML Canonicalization implementation.
- `pkg/types`: Internal XAdES-BES XML struct definitions for marshaling.

---

## ⚠️ Troubleshooting

### Legacy P12 Files

If you receive an error like `pkcs12: unknown digest algorithm`, it's often because the P12 was exported with modern algorithms not supported by older Go versions or specific environments.
**Solution**: Re-export your P12 using the `-legacy` flag in OpenSSL:

```bash
openssl pkcs12 -export -out legacy_signature.p12 -inkey key.pem -in cert.pem -legacy
```

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.

---

## 🙌 Thanks

Special thanks to [Bryan Calisto](https://github.com/bryancalisto) for the original TypeScript implementation which served as the foundation for this Go port.

---

_Maintained by [nelsonmarro](https://github.com/nelsonmarro)_

