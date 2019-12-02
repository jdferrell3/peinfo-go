package peinfo

import (
	// "bytes"
	"crypto/x509"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"io/ioutil"
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

func (cfg *ConfigT) VerifyCert(validateExpiredChain bool) (cert *x509.Certificate, verified bool, expired bool, err error) {
	expired = true

	idd := cfg.FindDataDirectory(pe.IMAGE_DIRECTORY_ENTRY_SECURITY)
	if cfg.Verbose {
		fmt.Printf("IMAGE_DIRECTORY_ENTRY_SECURITY virtual address: %d\n", idd.VirtualAddress)
		fmt.Printf("IMAGE_DIRECTORY_ENTRY_SECURITY size: %d\n", idd.Size)
	}

	if int64(idd.VirtualAddress) == 0 {
		err = fmt.Errorf("IMAGE_DIRECTORY_ENTRY_SECURITY not found")
		return nil, false, expired, err
	}

	c, err := readCert(cfg.OSFile, int64(idd.VirtualAddress), int64(idd.Size))
	if nil != err {
		err = fmt.Errorf("readCert failed: %s", err)
		return nil, false, expired, err
	}

	if c.CertificateType != WIN_CERT_TYPE_PKCS_SIGNED_DATA {
		return nil, false, expired, fmt.Errorf("only pkcs certificates supported (cert type = %d)", c.CertificateType)
	}

	if cfg.ExtractCert {
		f, _ := os.Create(fmt.Sprintf("%s.cer", cfg.FileName))
		defer f.Close()
		_, _ = f.Write(c.DER)
	}

	p7, err := pkcs7.Parse(c.DER)
	if nil != err {
		return nil, false, expired, err
	}

	cert = p7.GetOnlySigner()

	cp, err := getCertPool(cfg.RootCertDir)
	if nil != err {
		return nil, false, expired, err
	}

	expired, err = p7.VerifyWithChain(cp, validateExpiredChain)
	if nil == err {
		verified = true
	}

	for _, url := range cert.CRLDistributionPoints {
		revoked, ok, err := isCertRevoked(cert, url)
		if !revoked && !ok {
			return cert, false, expired, err
		}
		if revoked && ok {
			return cert, false, expired, fmt.Errorf("cert revoked: %v", err)
		}
		if revoked && !ok {
			return cert, false, expired, err
		}

	}

	return cert, verified, expired, err
}

func getCertPool(certDir string) (*x509.CertPool, error) {
	var cp *x509.CertPool

	// no CA store specifid, use system pool
	if certDir == "" {
		cp, err := x509.SystemCertPool()
		if nil != err {
			return nil, err
		}
		return cp, nil
	}

	cp = x509.NewCertPool()

	files, err := ioutil.ReadDir(certDir)
	if nil != err {
		return nil, err
	}

	appendedCert := false
	for _, file := range files {
		if !file.IsDir() {
			ext := filepath.Ext(file.Name())
			if ext == ".cer" || ext == ".crt" {
				dat, err := ioutil.ReadFile(filepath.Join(certDir, file.Name()))
				if nil != err {
					return cp, err
				}
				if !cp.AppendCertsFromPEM(dat) {
					err = fmt.Errorf("failed to append certs")
					return cp, err
				}
				appendedCert = true
			}
		}
	}

	if !appendedCert {
		return nil, fmt.Errorf("no CA certs added to pool")
	}

	return cp, nil
}
