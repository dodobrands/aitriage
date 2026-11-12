package main

import (
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {})
	// ruleid: GO-HTTP-DOS
	log.Fatal(http.ListenAndServe(":8080", nil))
}
