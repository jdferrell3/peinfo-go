package main

import (
	"debug/pe"
	"flag"
	"fmt"
	"log"
	"os"

	"peinfo"
)

func checkErr(err error) {
	if nil != err {
		log.Fatal(err)
	}
}

func main() {
	var showImports bool
	flag.BoolVar(&showImports, "imports", false, "show imports")
	flag.Parse()

	filePath := flag.Args()[0]

	fh, err := os.Open(filePath)
	checkErr(err)

	tempPE, err := pe.NewFile(fh)
	checkErr(err)

	file := peinfo.FileT{
		OSFile: fh,
		PEFile: tempPE}

	t := "pe32"
	if file.PEFile.Machine == pe.IMAGE_FILE_MACHINE_AMD64 {
		t = "pe32+"
	}
	fmt.Printf("type: %s\n", t)

	fmt.Printf("Characteristics: %v\n", file.GetCharacteristics())
	fmt.Printf("Subsystem: %v\n", file.GetImageSubSystem())

	cert, verified, err := file.VerifyCert()
	if cert != nil {
		fmt.Printf("\nCert:\n")
		fmt.Printf("  subject: %v\n", cert.Subject)
		fmt.Printf("  issuer: %v\n", cert.Issuer)
		fmt.Printf("  verified: %v\n", verified)
	}
	if nil != err {
		fmt.Printf("  error: %s\n", err)
	}

	vi, err := file.GetVersionInfo()
	if nil == err {
		fmt.Printf("\nVersion Info:\n")
		fmt.Printf("  %s\n", string(vi))
	} else {
		fmt.Printf("Error getting version info: %s\n", err)
	}

	if showImports {
		fmt.Printf("\nImports:\n")
		imports, err := file.PEFile.ImportedSymbols()
		if nil == err {
			for _, i := range imports {
				fmt.Printf(" - %s\n", i)
			}
		}
	}
}
