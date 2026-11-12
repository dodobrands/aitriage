package client

import (
	"crypto/tls"
	"net/http"
)

func Insecure() *http.Client {
	tr := &http.Transport{TLSClientConfig: &tls.Config{
		// ruleid: GO-TLS-SKIP
		InsecureSkipVerify: true,
	}}
	return &http.Client{Transport: tr}
}
