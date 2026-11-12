package config

import "embed"

//go:embed .env.example
var envExample string

//go:embed templates/secret_santa.html
var santa string

//go:embed static
var static embed.FS
