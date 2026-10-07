package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/time/rate"
)

func TestRateLimitKeepsDashboardAssetsAvailable(t *testing.T) {
	previousLimiter := globalLimiter
	globalLimiter = rate.NewLimiter(0, 1)
	t.Cleanup(func() { globalLimiter = previousLimiter })
	handler := RateLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	for _, tc := range []struct {
		path string
		want int
	}{
		{"/api/findings", http.StatusNoContent},
		{"/api/metrics", http.StatusTooManyRequests},
		{"/", http.StatusNoContent},
		{"/assets/dashboard.js", http.StatusNoContent},
		{"/assets/dashboard.css", http.StatusNoContent},
		{"/reports", http.StatusNoContent},
		{"/api/not-a-route", http.StatusTooManyRequests},
		{"/api", http.StatusTooManyRequests},
	} {
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, tc.path, nil))
		if rr.Code != tc.want {
			t.Fatalf("%s returned %d, want %d", tc.path, rr.Code, tc.want)
		}
		if tc.want == http.StatusTooManyRequests && rr.Header().Get("Content-Type") != "application/json" {
			t.Fatal("rate limit error lost its JSON response")
		}
	}
}
