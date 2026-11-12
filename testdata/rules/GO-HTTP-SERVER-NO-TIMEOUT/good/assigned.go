package main

import (
	"net/http"
	"time"
)

func newServer() *http.Server {
	srv := &http.Server{Addr: ":8080"}
	srv.ReadTimeout = 10 * time.Second
	return srv
}
