package secretvalue

import (
	"math"
	"testing"
)

func TestShannonEntropy(t *testing.T) {
	cases := map[string]float64{
		"":         0,
		"aaaa":     0,
		"ab":       1,
		"abcd":     2,
		"aabbccdd": 2,
	}
	for s, want := range cases {
		if got := ShannonEntropy(s); math.Abs(got-want) > 1e-9 {
			t.Errorf("ShannonEntropy(%q) = %v; want %v", s, got, want)
		}
	}
}

// LooksGenerated is the line between a value someone chose and one a
// generator produced; the built-in secret detector and the deploy audit both
// draw it here.
func TestLooksGenerated(t *testing.T) {
	generated := []string{
		"8f2Kq9vLx3TzR7mW4pYc",
		"dummy-Kq9zX2mW7pL4vT8nR",
		"exchangemeter-orbit-velvet-quartz",
		"u8Kq9zX2mW7pL4vT",
	}
	for _, v := range generated {
		if !LooksGenerated(v) {
			t.Errorf("LooksGenerated(%q) = false; want true", v)
		}
	}
	chosen := []string{
		"",
		"postgres",
		"q8#Kz!2",
		"Kq9zX2mW7pL4",
		"your-db-password",
		"correct-horse-battery-staple",
		"aaaaaaaaaaaaaaaaaaaa",
	}
	for _, v := range chosen {
		if LooksGenerated(v) {
			t.Errorf("LooksGenerated(%q) = true; want false", v)
		}
	}
}
