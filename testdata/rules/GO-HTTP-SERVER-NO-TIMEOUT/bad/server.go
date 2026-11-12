package main

import (
	"log"
	"net/http"
)

func main() {
	// ruleid: GO-HTTP-SERVER-NO-TIMEOUT
	srv := &http.Server{Addr: ":8080", Handler: http.DefaultServeMux}
	log.Fatal(srv.ListenAndServe())
}
