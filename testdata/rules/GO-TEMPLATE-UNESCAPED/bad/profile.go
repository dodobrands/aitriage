package web

import (
	"html/template"
	"net/http"
)

func Bio(r *http.Request) template.HTML {
	// ruleid: GO-TEMPLATE-UNESCAPED
	return template.HTML(r.FormValue("bio"))
}
