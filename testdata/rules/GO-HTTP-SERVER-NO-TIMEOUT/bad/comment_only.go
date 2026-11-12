package main

import (
	"log"
	"net/http"
)

func main() {
	// TODO: set ReadHeaderTimeout: 5 * time.Second
	// ruleid: GO-HTTP-SERVER-NO-TIMEOUT
	srv := &http.Server{
		Addr: ":8080",
	}
	log.Fatal(srv.ListenAndServe())
}
