package client

import (
	"context"
	"net/http"
	"sync"
	"time"
)

var (
	once   sync.Once
	client = &http.Client{Timeout: 10 * time.Second}
)

func Fetch(ctx context.Context, url string) (*http.Response, error) {
	once.Do(func() {})
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	return client.Do(req)
}

func Param(r *http.Request) string {
	return r.URL.Query().Get("id") + r.Header.Get("X-Request-Id")
}
