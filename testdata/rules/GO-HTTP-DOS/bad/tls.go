package main

import (
	"log"
	"net/http"
)

func main() {
	// ruleid: GO-HTTP-DOS
	log.Fatal(http.ListenAndServeTLS(":8443", "cert.pem", "key.pem", nil))
}
