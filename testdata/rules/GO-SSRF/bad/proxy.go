package api

import "net/http"

func Proxy(w http.ResponseWriter, r *http.Request) {
	// ruleid: GO-SSRF
	resp, err := http.Get(r.URL.Query().Get("url"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
}
