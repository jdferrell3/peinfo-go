package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/jdferrell3/peinfo-go/peinfo"
)

func checkErr(err error) {
	if nil != err {
		log.Fatal(err)
	}
}

func main() {
	var certDir string
	var extractCert bool
	var showImports bool
	var verbose bool
	var versionInfo bool
	flag.BoolVar(&extractCert, "extractcert", false, "extract cert from binary")
	flag.StringVar(&certDir, "certdir", "", "root CA dir")
	flag.BoolVar(&showImports, "imports", false, "show imports")
	flag.BoolVar(&verbose, "verbose", false, "verbose")
	flag.BoolVar(&versionInfo, "versioninfo", false, "show version info")
	flag.Parse()

	if len(flag.Args()) == 0 {
		fmt.Printf("Please specify PE file.\n\n")
		os.Exit(1)
	}

	filePath := flag.Args()[0]

	file, err := peinfo.Initialize(filePath, verbose, certDir, extractCert)
	checkErr(err)

	fmt.Printf("type: %s\n", file.GetPEType())

	fmt.Printf("TimeDateStamp: %v\n", file.GetTimeDateStamp())
	fmt.Printf("Characteristics: %v\n", file.GetCharacteristics())
	fmt.Printf("Subsystem: %v\n", file.GetImageSubSystem())

	cert, verified, expired, err := file.VerifyCert(true)
	if cert != nil {
		fmt.Printf("\nCert:\n")
		fmt.Printf("  subject: %v\n", cert.Subject)
		fmt.Printf("  issuer: %v\n", cert.Issuer)
		fmt.Printf("  not before: %v\n", cert.NotBefore)
		fmt.Printf("  not after: %v\n", cert.NotAfter)
		fmt.Printf("  CRL: %v\n", cert.CRLDistributionPoints)
		fmt.Printf("  verified: %v (chain expired: %v)\n", verified, expired)
	}
	if nil != err {
		fmt.Printf("  error: %s\n", err)
	}

	if versionInfo {
		vi, keys, err := file.GetVersionInfo()
		if nil == err && len(keys) > 0 {
			fmt.Printf("\nVersion Info:\n")

			for _, key := range keys {
				fmt.Printf(" %-20s : %s\n", key, vi[key])
			}
		} else {
			fmt.Printf("Error getting version info: %s\n", err)
		}
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
