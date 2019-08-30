package main

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"encoding/hex"
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
		fmt.Printf("  %s\n", hex.Dump(vi))
	} else {
		fmt.Printf("Error getting version info: %s\n", err)
	}

	// typedef struct {
	// 	WORD             wLength;
	// 	WORD             wValueLength;
	// 	WORD             wType;
	// 	WCHAR            szKey;
	// 	WORD             Padding1;
	// 	VS_FIXEDFILEINFO Value;
	// 	WORD             Padding2;
	// 	WORD             Children;
	//   } VS_VERSIONINFO;
	r := bytes.NewReader(vi)
	var wLength uint16
	binary.Read(r, binary.LittleEndian, &wLength)
	fmt.Printf("wLength: %d\n", wLength)

	var wValueLength uint16
	binary.Read(r, binary.LittleEndian, &wValueLength)
	fmt.Printf("wValueLength: %d\n", wValueLength)

	var wType uint16
	binary.Read(r, binary.LittleEndian, &wType)
	fmt.Printf("wType: %d\n", wType)

	var s []byte
	for true {
		var c [2]byte
		binary.Read(r, binary.LittleEndian, &c)
		fmt.Printf("c: %x\n", c)
		if c[0] == 0x00 && c[1] == 0x00 {
			s = append(s, c[0])
			s = append(s, c[1])
			break
		}
		s = append(s, c[0])
		s = append(s, c[1])
	}
	fmt.Printf("%s\n", string(s))

	var padding [2]byte
	binary.Read(r, binary.LittleEndian, &padding)

	// fmt.Printf("  %s\n", hex.Dump(r))

	var fixedFileInfo peinfo.VS_FIXEDFILEINFO
	binary.Read(r, binary.LittleEndian, &fixedFileInfo)
	fmt.Printf("%x", fixedFileInfo.DwSignature)

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
