package main

import "github.com/rs/cors"

func corsMiddleware() *cors.Cors {
	// ruleid: ENTR-CORS-WILDCARD
	return cors.New(cors.Options{AllowedOrigins: []string{"*"}})
}
