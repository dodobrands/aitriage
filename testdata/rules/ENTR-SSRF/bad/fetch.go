package web

import "net/http"

func preview(w http.ResponseWriter, r *http.Request) {
	// ruleid: ENTR-SSRF
	resp, err := http.Get(r.URL.Query().Get("u"))
	if err == nil {
		resp.Body.Close()
	}
}
