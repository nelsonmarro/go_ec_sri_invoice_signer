# 🇪🇨 Go EC SRI Invoice Signer

[![Go Reference](https://pkg.go.dev/badge/github.com/nelsonmarro/go_ec_sri_invoice_signer.svg)](https://pkg.go.dev/github.com/nelsonmarro/go_ec_sri_invoice_signer)
[![CI](https://github.com/nelsonmarro/go_ec_sri_invoice_signer/actions/workflows/ci.yml/badge.svg)](https://github.com/nelsonmarro/go_ec_sri_invoice_signer/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Una implementación robusta y nativa en Go para la firma de documentos electrónicos del **SRI Ecuador**, cumpliendo estrictamente con los estándares **XAdES-BES** y **Canonicalización Inclusiva**.

Esta librería soluciona los problemas comunes de "Firma Inválida" en Go al implementar correctamente la estructura de namespaces y algoritmos que exigen los validadores Java legacy del SRI.

---

## 🚀 Características

- **XAdES-BES Nativo**: Genera la estructura de firma exacta (incluyendo `QualifyingProperties` y `SignedProperties` con prefijos correctos).
- **Soporte Completo de Documentos**:
  - 🧾 `Factura` (v1.0.0 - v2.1.0)
  - 📉 `Nota de Crédito`
  - 📈 `Nota de Débito`
  - 🚛 `Guía de Remisión`
  - 💰 `Comprobante de Retención`
  - 🧺 `Liquidación de Compra`
  - Cualquier otro comprobante con `signer.Sign(xml, p12, "etiquetaRaiz", opts)`
- **Firma válida para cualquier XML bien formado**: el documento se canonicaliza (C14N 1.0) antes de calcular su digest, así que la firma no depende de cómo tu código serializó el XML (elementos vacíos `<x/>`, orden de atributos, saltos de línea CRLF, namespaces en la raíz, CDATA…).
- **Auto-verificación**: cada documento se verifica antes de devolverse; `signer.Verify` también está disponible para comprobar cualquier comprobante firmado.
- **Certificados reales**: lee archivos `.p12` que incluyen la cadena de la entidad certificadora (Security Data, UANATACA, Banco Central…) y elige el certificado que corresponde a la clave privada. Rechaza certificados caducados antes de firmar.
- **Seguridad**: Usa librerías criptográficas estándar de Go (`crypto/rsa`, `crypto/x509`) y `goxmldsig` para C14N confiable.
- **Sin CGO**: Compilación fácil y estática para cualquier SO.

---

## 📦 Instalación

```bash
go get github.com/nelsonmarro/go_ec_sri_invoice_signer
```

---

## 💻 Uso como Librería

La librería expone funciones específicas para cada tipo de documento, facilitando la integración.

```go
package main

import (
 "errors"
 "fmt"
 "os"
 "github.com/nelsonmarro/go_ec_sri_invoice_signer/pkg/signer"
)

func main() {
 // 1. Cargar el XML (previamente generado y validado con XSD)
 xmlBytes, _ := os.ReadFile("factura_generada.xml")
 xmlStr := string(xmlBytes)

 // 2. Cargar el archivo de firma (.p12)
 p12Bytes, _ := os.ReadFile("firma.p12")
 password := "TuContraseña123"

 // 3. Configurar opciones (SHA1 es el estándar actual del SRI)
 opts := &signer.SignOptions{
  Password:  password,
  Algorithm: signer.SHA1,
 }

 // 4. Firmar según el tipo de documento
 var signedXML string
 var err error

 // Ejemplo: Factura
 signedXML, err = signer.SignInvoice(xmlStr, p12Bytes, opts)

 // Otros métodos disponibles:
 // signedXML, err = signer.SignCreditNote(xmlStr, p12Bytes, opts)
 // signedXML, err = signer.SignDebitNote(xmlStr, p12Bytes, opts)
 // signedXML, err = signer.SignDeliveryGuide(xmlStr, p12Bytes, opts)
 // signedXML, err = signer.SignWithholdingCertificate(xmlStr, p12Bytes, opts)
 // signedXML, err = signer.SignPurchaseSettlement(xmlStr, p12Bytes, opts)
 // signedXML, err = signer.Sign(xmlStr, p12Bytes, signer.RootInvoice, opts) // genérico

 if errors.Is(err, signer.ErrCertificateExpired) {
  // La firma electrónica caducó: hay que renovarla antes de emitir.
 }
 if err != nil {
  panic(err)
 }

 fmt.Println(signedXML)
}
```

> **Nota:** el XML firmado se devuelve en forma canónica. Es el mismo documento, pero puede diferir del original en detalles sin significado (`<x/>` pasa a `<x></x>`, los atributos se reordenan, los comentarios se eliminan). Envía al SRI exactamente el texto que devuelve la librería, sin volver a formatearlo.

### Verificar un comprobante firmado

```go
if err := signer.Verify(signedXML); err != nil {
 // errors.Is(err, signer.ErrInvalidSignature): algún digest o la firma no coinciden
}
```

`Verify` recalcula el digest de cada referencia y comprueba la firma RSA sobre `SignedInfo`, igual que un validador XMLDSig estándar. No valida el certificado (cadena de confianza, revocación ni vigencia): eso lo hace el SRI al recibir el comprobante.

---

## 🛠 Herramienta de Pruebas (SRI Tester CLI)

La librería incluye una potente herramienta de línea de comandos (CLI) para realizar pruebas **End-to-End** contra el ambiente de pruebas del SRI. Esto es ideal para verificar que tu firma es válida antes de integrarla en tu aplicación.

### Instalación del CLI

Puedes instalar la herramienta globalmente en tu sistema:

```bash

go install github.com/nelsonmarro/go_ec_sri_invoice_signer/cmd/sri-tester@latest

```

Asegúrate de que tu `$GOPATH/bin` esté en tu PATH.

### Cómo usar el CLI

Una vez instalado, ejecuta el comando `sri-tester`:

```bash

# 1. Obtener ayuda y ver opciones

sri-tester --help

```

### Ejemplos de Prueba

**1. Probar Factura (Default):**

Genera una factura de prueba, la firma y la envía al SRI.

```bash

sri-tester sign-send \
  -p12 ruta/a/tu/firma.p12 \
  -pass tu_contraseña \
  -ruc 1700000000001

# puedes agregar el flag -type factura si quieres ser especifico

```

**2. Probar Nota de Crédito:**

```bash

sri-tester sign-send \
  -p12 firma.p12 \
  -pass 1234 -ruc 1700000000001 \
  -type notaCredito

```

**3. Probar Comprobante de Retención:**

```bash
sri-tester sign-send \
  -p12 firma.p12 \
  -pass 1234 -ruc 1700000000001 \
  -type comprobanteRetencion
```

### Interpretación de Resultados

El CLI te mostrará el progreso en tiempo real:

1. **Generación:** Crea un XML válido con Clave de Acceso aleatoria.
2. **Firma:** Aplica la firma XAdES-BES.
3. **Envío (Recepción):**
   - `✅ SRI Status: RECIBIDA`: El SRI recibió el XML y pasó la validación inicial (firma y esquema).
   - `❌ SRI Status: DEVUELTA`: Error en el XML o firma (el mensaje detallado se imprimirá).
4. **Autorización (Consulta):** Espera 3 segundos y consulta el estado final.
   - `🎉 Result: AUTORIZADO`: ¡Éxito total! Tu firma funciona.
   - `⏳ Result: EN PROCESO`: El SRI está lento, pero el documento es válido.
   - `❌ Result: NO AUTORIZADO`: El SRI rechazó el documento (ej: RUC clausurado, error lógico).

---

## 🏗 Detalles Técnicos

1. **Canonicalización Inclusiva**: El SRI requiere estrictamente `REC-xml-c14n-20010315`. Usamos `goxmldsig` para garantizar el cumplimiento, ya que las librerías por defecto de Go suelen usar C14N Exclusivo (pensado para SAML).
2. **Aislamiento de Namespaces**: Para evitar el error "Firma Inválida" (Error 39), los namespaces de XAdES (`etsi`) se declaran localmente en sus respectivos nodos (`QualifyingProperties`), evitando que ensucien el hash del nodo `SignedInfo` durante la canonicalización.
3. **Digest sobre la forma canónica**: el validador del SRI aplica la transformación `enveloped-signature` y luego canonicaliza el documento antes de calcular su digest. La librería hace lo mismo: canonicaliza el comprobante, calcula el digest sobre ese resultado y devuelve el documento en esa misma forma canónica, de modo que el digest coincide por construcción. (Hasta la v1.0.0 se hasheaban los bytes de entrada tal cual, lo que solo funcionaba si el XML ya venía en forma canónica.)
4. **Canonicalización en contexto**: `SignedProperties`, `KeyInfo` y `SignedInfo` se canonicalizan ya insertados en el documento, por lo que los namespaces declarados en la raíz del comprobante (p. ej. `xmlns:xsi`) entran en sus digests tal como los verá el validador.
5. **Interoperabilidad comprobada**: la suite de tests verifica las firmas con `xmlsec1` (una implementación independiente de XMLDSig) cuando está instalado, y compara la salida contra documentos de referencia generados por la v1.0.0.

---

## 📄 Licencia

Distribuido bajo la Licencia MIT. Ver `LICENSE` para más detalles.

_Mantenido por [nelsonmarro](https://github.com/nelsonmarro)_
