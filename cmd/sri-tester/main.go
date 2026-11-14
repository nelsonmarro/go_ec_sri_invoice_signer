package main

import (
	"bytes"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/nelsonmarro/go_ec_sri_invoice_signer/pkg/signer"
)

//go:embed templates/*.xml
var templateFS embed.FS

const (
	SRI_RECEPCION_PRUEBAS    = "https://celcer.sri.gob.ec/comprobantes-electronicos-ws/RecepcionComprobantesOffline"
	SRI_AUTORIZACION_PRUEBAS = "https://celcer.sri.gob.ec/comprobantes-electronicos-ws/AutorizacionComprobantesOffline"
)

func main() {
	cmd := flag.NewFlagSet("sri-tester", flag.ExitOnError)
	p12Path := cmd.String("p12", "", "Ruta al archivo .p12")
	pass := cmd.String("pass", "", "Contraseña del archivo .p12")
	xmlType := cmd.String("type", "factura", "Tipo de documento: factura, notaCredito, notaDebito, guiaRemision, comprobanteRetencion")
	ruc := cmd.String("ruc", "1790000000001", "RUC del emisor")
	verbose := cmd.Bool("verbose", false, "Habilitar salida detallada (XML firmado y respuestas completas)")

	cmd.Usage = func() {
		fmt.Println("🇪🇨 SRI Tester CLI - Herramienta de pruebas para firma electrónica SRI")
		fmt.Println("\nUso:")
		fmt.Println("  sri-tester <subcomando> [opciones]")
		fmt.Println("\nSubcomandos:")
		fmt.Println("  sign-send    Genera un XML de prueba, lo firma y lo envía al SRI (Ambiente Pruebas)")
		fmt.Println("\nOpciones obligatorias:")
		fmt.Println("  -p12 <ruta>  Ruta al archivo de firma electrónica (.p12)")
		fmt.Println("  -pass <pwd>  Contraseña del archivo .p12")
		fmt.Println("\nOpciones adicionales:")
		fmt.Println("  -ruc <ruc>   RUC del emisor (Defecto: 1790000000001)")
		fmt.Println("  -type <tipo> Tipo de comprobante a generar:")
		fmt.Println("               factura (default), notaCredito, notaDebito, guiaRemision, comprobanteRetencion")
		fmt.Println("  -verbose     Muestra logs detallados del XML y respuestas SOAP")
		fmt.Println("\nEjemplos:")
		fmt.Println("  # Prueba básica:")
		fmt.Println("  sri-tester sign-send -p12 firma.p12 -pass 1234")
		fmt.Println("\n  # Prueba detallada con otro documento:")
		fmt.Println("  sri-tester sign-send -p12 firma.p12 -pass 1234 -type notaCredito -verbose")
	}

	if len(os.Args) < 2 || os.Args[1] == "--help" || os.Args[1] == "-h" {
		cmd.Usage()
		os.Exit(0)
	}

	// El primer argumento es el subcomando, parseamos el resto
	cmd.Parse(os.Args[2:])

	if *p12Path == "" || *pass == "" {
		fmt.Println("❌ Error: Las opciones -p12 y -pass son obligatorias.")
		fmt.Println("Ejecute con --help para ver las instrucciones.")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "sign-send":
		runSignSend(*p12Path, *pass, *xmlType, *ruc, *verbose)
	default:
		fmt.Printf("Subcomando desconocido: %s\n", os.Args[1])
		cmd.Usage()
		os.Exit(1)
	}
}

func runSignSend(p12Path, pass, docType, ruc string, verbose bool) {
	fmt.Printf("⚙️  Config: Type=%s, RUC=%s, Verbose=%v\n", docType, ruc, verbose)

	// 1-2. Código SRI del tipo de documento
	sriCode, ok := sriDocCodes[docType]
	if !ok {
		panic("Tipo de documento desconocido para la generación del código SRI")
	}

	// 3. Generar Datos
	accessKey := generateAccessKey(ruc, sriCode)
	fmt.Printf("🔑 Clave de Acceso Generada: %s (Tipo: %s)\n", accessKey, docType)

	// 4. Cargar el template embebido y reemplazar placeholders
	xmlStr, err := renderTemplate(docType, ruc, accessKey, time.Now())
	if err != nil {
		panic(err.Error())
	}

	// 5. Firmar
	fmt.Println("✍️  Firmando XML...")
	p12Bytes, err := os.ReadFile(p12Path)
	if err != nil {
		panic(err)
	}

	opts := &signer.SignOptions{Password: pass}
	var signedXML string

	switch docType {
	case "factura":
		signedXML, err = signer.SignInvoice(xmlStr, p12Bytes, opts)
	case "notaCredito":
		signedXML, err = signer.SignCreditNote(xmlStr, p12Bytes, opts)
	case "notaDebito":
		signedXML, err = signer.SignDebitNote(xmlStr, p12Bytes, opts)
	case "guiaRemision":
		signedXML, err = signer.SignDeliveryGuide(xmlStr, p12Bytes, opts)
	case "comprobanteRetencion":
		signedXML, err = signer.SignWithholdingCertificate(xmlStr, p12Bytes, opts)
	default:
		panic("Tipo de documento no soportado para firma")
	}

	if err != nil {
		panic(fmt.Sprintf("Falla al firmar: %v", err))
	}

	if verbose {
		fmt.Println("\n--- 📄 XML FIRMADO 📄 ---")
		fmt.Println(signedXML)
		fmt.Println("--------------------------")
	}

	// 6. Enviar al SRI
	fmt.Println("🚀 Enviando al SRI (Ambiente de Pruebas)...")
	sendToSRI(signedXML, verbose)

	// 7. Consultar Autorización
	fmt.Println("⏳ Consultando Autorización (esperando 3s)...")
	time.Sleep(3 * time.Second)
	checkAuthorization(accessKey, verbose)
}

// --- Helpers ---

// sriDocCodes maps each supported document type (its root element and
// template name) to the SRI document code.
var sriDocCodes = map[string]string{
	"factura":              "01",
	"notaCredito":          "04",
	"notaDebito":           "05",
	"guiaRemision":         "06",
	"comprobanteRetencion": "07",
}

// renderTemplate loads the embedded template of docType and fills in its placeholders.
func renderTemplate(docType, ruc, accessKey string, now time.Time) (string, error) {
	if _, ok := sriDocCodes[docType]; !ok {
		return "", fmt.Errorf("tipo de documento desconocido: %s", docType)
	}
	templatePath := fmt.Sprintf("templates/%s.xml", docType)
	tmplBytes, err := templateFS.ReadFile(templatePath)
	if err != nil {
		return "", fmt.Errorf("error al cargar el template embebido %s: %w", templatePath, err)
	}
	return strings.NewReplacer(
		"{{claveAcceso}}", accessKey,
		"{{ruc}}", ruc,
		"{{ambiente}}", "1", // Pruebas
		"{{razonSocial}}", "PRUEBAS SRI",
		"{{nombreComercial}}", "PRUEBAS",
		"{{estab}}", "001",
		"{{ptoEmi}}", "001",
		"{{secuencial}}", accessKey[30:39],
		"{{dirMatriz}}", "Quito",
		"{{dirEstablecimiento}}", "Quito",
		"{{fechaEmision}}", now.Format("02/01/2006"),
		"{{periodoFiscal}}", now.Format("01/2006"),
	).Replace(string(tmplBytes)), nil
}

func generateAccessKey(ruc, tipo string) string {
	date := time.Now().Format("02012006")
	// tipo viene como argumento
	ambiente := "1"
	serie := "001001"
	secuencial := fmt.Sprintf("%09d", time.Now().Unix()%1000000000) // Secuencia aleatoria basada en tiempo

	nSafe, _ := rand.Int(rand.Reader, big.NewInt(100000000))
	codigoNum := fmt.Sprintf("%08d", nSafe.Int64())

	key48 := date + tipo + ruc + ambiente + serie + secuencial + codigoNum + "1" // Emisión Normal

	// Modulo 11
	sum := 0
	factor := 2
	for i := len(key48) - 1; i >= 0; i-- {
		digit := int(key48[i] - '0')
		sum += digit * factor
		factor++
		if factor > 7 {
			factor = 2
		}
	}
	verificador := 11 - (sum % 11)
	if verificador == 11 {
		verificador = 0
	}
	if verificador == 10 {
		verificador = 1
	}

	return key48 + fmt.Sprintf("%d", verificador)
}

func sendToSRI(xmlStr string, verbose bool) {
	b64 := base64.StdEncoding.EncodeToString([]byte(xmlStr))
	envelope := fmt.Sprintf(`<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ec="http://ec.gob.sri.ws.recepcion">
   <soapenv:Header/>
   <soapenv:Body>
      <ec:validarComprobante>
         <xml>%s</xml>
      </ec:validarComprobante>
   </soapenv:Body>
</soapenv:Envelope>`, b64)

	resp, err := http.Post(SRI_RECEPCION_PRUEBAS, "text/xml", bytes.NewBufferString(envelope))
	if err != nil {
		fmt.Printf("❌ Error de red: %v\n", err)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	if verbose {
		fmt.Println("\n--- 📡 RESPUESTA RECEPCIÓN SRI ---")
		// Pretty print simple para XML
		fmt.Println(formatXML(bodyStr))
		fmt.Println("----------------------------------")
	}

	// Imprimir un resumen conciso
	if strings.Contains(bodyStr, "RECIBIDA") {
		fmt.Println("✅ Estado SRI: RECIBIDA")
	} else if strings.Contains(bodyStr, "DEVUELTA") {
		fmt.Println("❌ Estado SRI: DEVUELTA")
		if !verbose {
			// Si no es verbose, intentamos mostrar al menos el mensaje de error clave
			// Una extracción simple para no parsear todo el XML en el helper
			start := strings.Index(bodyStr, "<mensaje>")
			end := strings.Index(bodyStr, "</mensaje>")
			if start != -1 && end != -1 {
				fmt.Printf("   Motivo: %s\n", bodyStr[start+9:end])
			} else {
				fmt.Println("   (Use -verbose para ver el detalle)")
			}
		}
	} else {
		if !verbose {
			fmt.Println("⚠️  Respuesta SRI inesperada (Use -verbose para ver)")
		}
	}
}

func checkAuthorization(accessKey string, verbose bool) {
	envelope := fmt.Sprintf(`<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ec="http://ec.gob.sri.ws.autorizacion">
   <soapenv:Header/>
   <soapenv:Body>
      <ec:autorizacionComprobante>
         <claveAccesoComprobante>%s</claveAccesoComprobante>
      </ec:autorizacionComprobante>
   </soapenv:Body>
</soapenv:Envelope>`, accessKey)

	resp, err := http.Post(SRI_AUTORIZACION_PRUEBAS, "text/xml", bytes.NewBufferString(envelope))
	if err != nil {
		fmt.Printf("❌ Error de red: %v\n", err)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	if verbose {
		fmt.Println("\n--- 📡 RESPUESTA AUTORIZACIÓN SRI ---")
		fmt.Println(formatXML(bodyStr))
		fmt.Println("-------------------------------------")
	}

	// Salida concisa
	if strings.Contains(bodyStr, "AUTORIZADO") && !strings.Contains(bodyStr, "NO AUTORIZADO") {
		fmt.Println("🎉 Resultado: AUTORIZADO")
	} else if strings.Contains(bodyStr, "NO AUTORIZADO") {
		fmt.Println("❌ Resultado: NO AUTORIZADO")
		if idx := strings.Index(bodyStr, "<mensaje>"); idx != -1 {
			endIdx := strings.Index(bodyStr, "</mensaje>")
			fmt.Printf("   Mensaje: %s\n", bodyStr[idx+9:endIdx])
		}
	} else if strings.Contains(bodyStr, "numeroComprobantes>0") {
		fmt.Println("⏳ Resultado: EN PROCESO (El SRI aún no tiene respuesta)")
	} else {
		if !verbose {
			fmt.Printf("Respuesta de Autorización SRI desconocida (Use -verbose)\n")
		}
	}
}

// formatXML intenta formatear el XML para que sea legible en consola (indentación básica)
func formatXML(xmlStr string) string {
	var out bytes.Buffer
	decoder := xml.NewDecoder(strings.NewReader(xmlStr))
	encoder := xml.NewEncoder(&out)
	encoder.Indent("", "  ")

	// Decodificar y volver a codificar para indentar
	var dummy any
	if err := decoder.Decode(&dummy); err == nil {
		return xmlStr
	}

	// Fallback: reemplazo simple para legibilidad
	formatted := strings.ReplaceAll(xmlStr, "><", ">\n<")
	return formatted
}
