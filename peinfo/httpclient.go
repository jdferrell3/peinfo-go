package peinfo

import (
	"net"
	"net/http"
	"time"
)

const HTTP_TIMEOUT = 15

// NewHTTPClient returns a *http.Client with timeouts test
func newHTTPClient() *http.Client {
	var netTransport = &http.Transport{
		Dial: (&net.Dialer{
			Timeout: time.Second * HTTP_TIMEOUT,
		}).Dial,
		TLSHandshakeTimeout: time.Second * HTTP_TIMEOUT,
	}

	return &http.Client{
		Timeout:   time.Second * HTTP_TIMEOUT,
		Transport: netTransport,
	}
}
