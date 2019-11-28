package main

import (
	"debug/pe"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/jdferrell3/peinfo-go/peinfo"
)

func checkErr(err error) {
	if nil != err {
		log.Fatal(err)
	}
}

func main() {
	var extractCert bool
	var showImports bool
	var verbose bool
	flag.BoolVar(&extractCert, "extractCert", false, "extract cert from binary")
	flag.BoolVar(&showImports, "imports", false, "show imports")
	flag.BoolVar(&verbose, "verbose", false, "verbose")
	flag.Parse()

	if len(flag.Args()) == 0 {
		fmt.Printf("Please specify PE file.\n\n")
		os.Exit(1)
	}

	filePath := flag.Args()[0]

	fh, err := os.Open(filePath)
	checkErr(err)

	tempPE, err := pe.NewFile(fh)
	checkErr(err)

	file := peinfo.FileT{
		FileName:    filepath.Base(filePath),
		OSFile:      fh,
		PEFile:      tempPE,
		Verbose:     verbose,
		ExtractCert: extractCert,
	}

	fmt.Printf("type: %s\n", file.GetPEType())

	fmt.Printf("TimeDateStamp: %v\n", file.GetTimeDateStamp())
	fmt.Printf("Characteristics: %v\n", file.GetCharacteristics())
	fmt.Printf("Subsystem: %v\n", file.GetImageSubSystem())

	cert, verified, err := file.VerifyCert()
	if cert != nil {
		fmt.Printf("\nCert:\n")
		fmt.Printf("  subject: %v\n", cert.Subject)
		fmt.Printf("  issuer: %v\n", cert.Issuer)
		fmt.Printf("  not before: %v\n", cert.NotBefore)
		fmt.Printf("  not after: %v\n", cert.NotAfter)
		fmt.Printf("  verified: %v\n", verified)
	}
	if nil != err {
		fmt.Printf("  error: %s\n", err)
	}

	vi, keys, err := file.GetVersionInfo()
	if nil == err {
		fmt.Printf("\nVersion Info:\n")

		for _, key := range keys {
			fmt.Printf(" %-20s : %s\n", key, vi[key])
		}
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
