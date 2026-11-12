package web

import "net/http"

func next(w http.ResponseWriter, r *http.Request) {
	// ruleid: ENTR-OPEN-REDIRECT
	http.Redirect(w, r, r.URL.Query().Get("next"), http.StatusFound)
}
