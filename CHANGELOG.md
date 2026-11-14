# Changelog

## v1.1.0

### Corregido

- **Digest del documento sobre la forma canónica.** Antes se hasheaban los bytes de entrada tal cual; si el XML no venía ya en forma canónica (un elemento vacío `<x/>`, atributos en otro orden, saltos CRLF, CDATA, comentarios, namespaces en la raíz), la firma resultante era inválida para cualquier validador estándar. Ahora el comprobante se canonicaliza (C14N 1.0) antes de calcular el digest y se devuelve en esa misma forma. Para un XML que ya era canónico, la salida es idéntica byte a byte a la de la v1.0.0.
- **Archivos `.p12` con cadena de certificación.** `ParsePKCS12` fallaba con `expected exactly two safe bags` cuando el archivo incluía los certificados de la entidad certificadora, que es lo habitual en Ecuador. Ahora se acepta la cadena y se usa el certificado cuya clave pública corresponde a la clave privada, aunque no sea el primero del archivo.
- **`X509IssuerName` con comas.** Un emisor como `O=ACME, S.A.` perdía el espacio tras la coma escapada. Ahora se emite el nombre RFC 2253 sin alterar.
- **Referencia al `id` real de la raíz.** Si el comprobante traía un `id` distinto de `comprobante`, la referencia apuntaba a un elemento inexistente; si no traía `id`, se añadía al árbol pero no al documento firmado.
- **Dependencias con vulnerabilidades conocidas actualizadas**: `go-pkcs12` 0.7.0 → 0.7.4 (GO-2026-5052) y `goxmldsig` 1.5.0 → 1.6.1 (GO-2026-4753), además de `etree` y `x/crypto`. `govulncheck` queda limpio. La versión mínima de Go pasa a 1.26.
- Los errores de canonicalización ya no se ignoran, y un XML sin elemento raíz devuelve un error en lugar de provocar un pánico.

### Añadido

- `Verify(signedXML)`: verifica los digests de todas las referencias y la firma RSA. Cada documento se auto-verifica antes de devolverse.
- `Sign(xml, p12, rootTag, opts)`: firma genérica para cualquier etiqueta raíz, con las constantes `Root*`.
- `SignPurchaseSettlement` para liquidaciones de compra.
- `ErrCertificateExpired` y `ErrCertificateNotYetValid`: el certificado se valida contra la fecha actual antes de firmar.
- Se comprueba que la etiqueta raíz del XML sea la del tipo de comprobante que se pidió firmar.
- CI con GitHub Actions (formato, `go vet`, tests con `-race`, `govulncheck`) y tests de interoperabilidad con `xmlsec1`.

### Cambios de comportamiento a tener en cuenta

- El XML firmado se devuelve en forma canónica: los comentarios se eliminan, `<x/>` pasa a `<x></x>` y los atributos pueden cambiar de orden.
- Firmar con un certificado caducado ahora devuelve un error en lugar de producir un comprobante que el SRI rechazaría.
