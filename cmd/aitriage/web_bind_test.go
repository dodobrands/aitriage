package main

import "testing"

func TestWebListenAddress(t *testing.T) {
	for _, tc := range []struct{ runtime, want string }{
		{"", "127.0.0.1:8080"},
		{"native", "127.0.0.1:8080"},
		{"unexpected", "127.0.0.1:8080"},
		{"container", "0.0.0.0:8080"},
	} {
		if got := webListenAddress(8080, tc.runtime); got != tc.want {
			t.Errorf("runtime %q: %s, want %s", tc.runtime, got, tc.want)
		}
	}
}
