package peinfo

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io/ioutil"
	"net/http"
)

// The functions in this file are based on CloudFlare's "revoke" package:
// https://github.com/cloudflare/cfssl/blob/9c027c93ba9e044bfffb63b78f9174075413bc9e/revoke/revoke.go
// See LICENSE for copyright.

// isCertRevoked checks the certificate against a CRL. It returns a pair of
// booleans:
// - `revoked` indicates whether the certificate is revoked
// - `ok` indicates whether the revocations were successfully checked.
// This leads to the following combinations:
//
//  false, false: an error was encountered while checking revocations.
//
//  false, true:  the certificate was checked successfully and
//                  it is not revoked.
//
//  true, true:   the certificate was checked successfully and
//                  it is revoked.
//
//  true, false:  failure to check revocation status causes
//                  verification to fail
func isCertRevoked(cert *x509.Certificate, url string) (revoked bool, ok bool, err error) {
	crl, err := getCRL(url)
	if nil != err {
		return false, false, err
	}

	for _, revokedCert := range crl.TBSCertList.RevokedCertificates {
		if cert.SerialNumber.Cmp(revokedCert.SerialNumber) == 0 {
			err = fmt.Errorf("serial number match: certificate was revoked")
			return true, true, err
		}
	}

	return false, true, err
}

// getCRL HTTP GET's and parses a CRL, returns a *pkix.CertificateList
func getCRL(url string) (*pkix.CertificateList, error) {
	client := newHTTPClient()
	resp, err := client.Get(url)
	if nil != err {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get CRL: HTTP status = %d", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if nil != err {
		return nil, err
	}
	resp.Body.Close()

	return x509.ParseCRL(body)
}
