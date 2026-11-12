package api

import (
	"context"
	"net/http"
)

func Fetch(ctx context.Context, reqURL string) (*http.Request, error) {
	return http.NewRequestWithContext(ctx, "GET", reqURL, nil)
}

// job is not an HTTP request, even though the variable is called r.
type job struct{ Method, URL string }

func Replay(r job) (*http.Request, error) {
	return http.NewRequest(r.Method, r.URL, nil)
}
