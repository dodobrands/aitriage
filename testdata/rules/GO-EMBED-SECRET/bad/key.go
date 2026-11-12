package config

import _ "embed"

// ruleid: GO-EMBED-SECRET
//go:embed certs/server.crt certs/server.key
var serverKey []byte
