package engine

import (
	"strings"
	"unicode"

	"github.com/dodobrands/aitriage/internal/scanner/secretvalue"
)

// CalculateShannonEntropy calculates the Shannon entropy of a string.
// It returns a value representing the "randomness" of the string. The
// computation lives in secretvalue, which the deploy audit shares.
func CalculateShannonEntropy(data string) float64 {
	return secretvalue.ShannonEntropy(data)
}

// IsHighEntropy returns true if the string looks like a potential secret (high entropy + specific length).
func IsHighEntropy(s string) bool {
	// Trim quotes and whitespace
	s = strings.Trim(s, " \"'`\t\n\r")

	// Too short for a meaningful secret
	if len(s) < 16 {
		return false
	}

	// Too long (might be a large blob of data)
	if len(s) > 128 {
		return false
	}

	// Contains non-printable characters or many non-alphanumeric (likely binary)
	nonAlnum := 0
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return false
		}
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' && r != '_' && r != '+' && r != '=' && r != '/' {
			nonAlnum++
		}
	}

	// If more than 30% are weird characters, skip
	if float64(nonAlnum)/float64(len(s)) > 0.3 {
		return false
	}

	entropy := CalculateShannonEntropy(s)

	// Base64-like strings usually have entropy > 3.5
	// Hex strings usually > 3.0
	// We'll use 3.7 as a conservative threshold for "possible secret"
	return entropy > 3.7
}
