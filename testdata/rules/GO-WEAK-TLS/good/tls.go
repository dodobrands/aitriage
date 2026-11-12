package server

import "crypto/tls"

var versionNames = map[uint16]string{
	tls.VersionTLS10: "TLS 1.0",
	tls.VersionTLS11: "TLS 1.1",
	tls.VersionTLS12: "TLS 1.2",
}

func Config() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12}
}
