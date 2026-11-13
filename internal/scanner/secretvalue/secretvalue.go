// Package secretvalue holds what the secret checks share about a value itself:
// how random it is, and whether it is random enough to have been generated
// rather than chosen. The built-in secret detector and the deploy audit both
// use it, so they agree on what a generated secret looks like.
package secretvalue

import "math"

// ShannonEntropy returns the Shannon entropy of s in bits per character: how
// random it looks.
func ShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	charCounts := make(map[rune]int)
	for _, char := range s {
		charCounts[char]++
	}

	var entropy float64
	length := float64(len(s))
	for _, count := range charCounts {
		p := float64(count) / length
		entropy -= p * math.Log2(p)
	}

	return entropy
}

// LooksGenerated reports whether a value is long and random enough to be a
// generated secret (an API key, a token, a random password) rather than a
// word, a name or a phrase: at least 16 bytes above 3.5 bits per character,
// or at least 12 bytes above 4.0. It is the threshold the built-in secret
// detector applies to a value assigned to a secret-named variable.
func LooksGenerated(v string) bool {
	entropy := ShannonEntropy(v)
	return len(v) >= 16 && entropy > 3.5 || len(v) >= 12 && entropy > 4.0
}
