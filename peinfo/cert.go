package peinfo

import (
	// "bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"debug/pe"
	"encoding/binary"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"

	// "github.com/fullsailor/pkcs7"
	// "go.mozilla.org/pkcs7"
	"github.com/jdferrell3/pkcs7"
)

const (
	WIN_CERT_REVISION_1_0 = 0x0100
	WIN_CERT_REVISION_2_0 = 0x0200

	WIN_CERT_TYPE_X509             = 0x0001
	WIN_CERT_TYPE_PKCS_SIGNED_DATA = 0x0002
	WIN_CERT_TYPE_RESERVED_1       = 0x0003
	WIN_CERT_TYPE_TS_STACK_SIGNED  = 0x0004
)

func readCert(fh *os.File, offset int64, size int64) (cert CertDetails, err error) {
	_, err = fh.Seek(int64(offset), os.SEEK_SET)
	if nil != err {
		return cert, err
	}

	var dwLength uint32
	err = binary.Read(fh, binary.LittleEndian, &dwLength)
	if nil != err {
		return cert, err
	}
	// fmt.Printf("dwLength: %d\n", dwLength)

	var wRevision uint16
	err = binary.Read(fh, binary.LittleEndian, &wRevision)
	if nil != err {
		return cert, err
	}
	// fmt.Printf("wRevision: %x\n", wRevision)

	var wCertificateType uint16
	err = binary.Read(fh, binary.LittleEndian, &wCertificateType)
	if nil != err {
		return cert, err
	}
	// fmt.Printf("wCertificateType: %x\n", wCertificateType)

	data := make([]byte, dwLength)
	_, err = fh.Read(data)
	if nil != err {
		return cert, err
	}

	c := CertDetails{
		Length:          dwLength,
		Revision:        wRevision,
		CertificateType: wCertificateType,
		DER:             data,
	}

	return c, nil
}

func (f *FileT) VerifyCert(validateExpiredChain bool) (cert *x509.Certificate, verified bool, expired bool, err error) {
	expired = true

	idd := f.FindDataDirectory(pe.IMAGE_DIRECTORY_ENTRY_SECURITY)
	if f.Verbose {
		fmt.Printf("IMAGE_DIRECTORY_ENTRY_SECURITY virtual address: %d\n", idd.VirtualAddress)
		fmt.Printf("IMAGE_DIRECTORY_ENTRY_SECURITY size: %d\n", idd.Size)
	}

	if int64(idd.VirtualAddress) == 0 {
		err = fmt.Errorf("IMAGE_DIRECTORY_ENTRY_SECURITY not found")
		return nil, false, expired, err
	}

	c, err := readCert(f.OSFile, int64(idd.VirtualAddress), int64(idd.Size))
	if nil != err {
		err = fmt.Errorf("readCert failed: %s", err)
		return nil, false, expired, err
	}

	if c.CertificateType != WIN_CERT_TYPE_PKCS_SIGNED_DATA {
		return nil, false, expired, fmt.Errorf("only pkcs certificates supported (cert type = %d)", c.CertificateType)
	}

	if f.ExtractCert {
		f, _ := os.Create(fmt.Sprintf("%s.cer", f.FileName))
		defer f.Close()
		_, _ = f.Write(c.DER)
	}

	p7, err := pkcs7.Parse(c.DER)
	if nil != err {
		return nil, false, err
	}

	cert = p7.GetOnlySigner()

	cp, err := x509.SystemCertPool()
	if nil != err {
		return nil, false, err
	}
	// cp := x509.NewCertPool()

	err = p7.VerifyWithChain(cp)
	if nil == err {
		verified = true
	}

	return cert, verified, err
}
