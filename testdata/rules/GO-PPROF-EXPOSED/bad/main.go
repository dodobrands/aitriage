package main

import (
	"log"
	"net/http"
	// ruleid: GO-PPROF-EXPOSED
	_ "net/http/pprof"
)

func main() {
	log.Fatal(http.ListenAndServe(":8080", nil))
}
