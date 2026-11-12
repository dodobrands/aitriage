package web

import (
	"html/template"
	"net/http"
)

func Banner() template.HTML {
	return template.HTML("<b>Welcome</b>")
}

// The template escapes plain strings.
func Bio(r *http.Request) string {
	return r.FormValue("bio")
}
