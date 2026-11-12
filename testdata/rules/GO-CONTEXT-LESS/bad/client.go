package client

import "net/http"

func Fetch(url string) (*http.Response, error) {
	// ruleid: GO-CONTEXT-LESS
	return http.Get(url)
}
