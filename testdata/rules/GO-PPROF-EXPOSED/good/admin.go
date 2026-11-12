package main

import (
	"net/http"
	"net/http/pprof"
)

// Profiling is served on a separate admin mux bound to localhost.
func adminMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	return mux
}
