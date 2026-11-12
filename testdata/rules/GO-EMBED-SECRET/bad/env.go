package config

import _ "embed"

// ruleid: GO-EMBED-SECRET
//go:embed .env
var env string
