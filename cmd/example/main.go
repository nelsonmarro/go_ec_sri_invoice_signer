package main

import (
	"fmt"
	"os"

	"github.com/nelsonmarro/go_ec_sri_invoice_signer/pkg/signer"
)

func main() {
	if len(os.Args) < 4 {
		fmt.Println("Usage: example <xml_file> <p12_file> <password>")
		return
	}

	xmlPath := os.Args[1]
	p12Path := os.Args[2]
	password := os.Args[3]

	xmlBytes, err := os.ReadFile(xmlPath)
	if err != nil {
		panic(err)
	}

	p12Bytes, err := os.ReadFile(p12Path)
	if err != nil {
		panic(err)
	}

	signedXML, err := signer.SignInvoice(string(xmlBytes), p12Bytes, &signer.SignOptions{
		Password: password,
	})
	if err != nil {
		panic(err)
	}

	fmt.Println(signedXML)
}
