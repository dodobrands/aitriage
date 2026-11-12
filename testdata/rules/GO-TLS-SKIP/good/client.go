package client

import "crypto/tls"

// InsecureSkipVerify: true is never set here; a private CA goes into RootCAs.
func Config(skip bool) *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: false}
}
