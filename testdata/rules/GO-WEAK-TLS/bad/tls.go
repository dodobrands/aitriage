package server

import "crypto/tls"

func Config() *tls.Config {
	return &tls.Config{
		// ruleid: GO-WEAK-TLS
		MinVersion: tls.VersionTLS10,
	}
}
