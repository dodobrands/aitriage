package main

import (
	"log"
	"net/http"
)

func main() {
	log.Fatal(http.ListenAndServe("127.0.0.1:9090", nil)) // aitriage-ignore: GO-HTTP-DOS (local metrics port)
}
