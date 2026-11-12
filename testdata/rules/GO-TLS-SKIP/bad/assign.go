package client

import "crypto/tls"

func Config() *tls.Config {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	// ruleid: GO-TLS-SKIP
	cfg.InsecureSkipVerify = true
	return cfg
}
