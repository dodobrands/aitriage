package auth

// ruleid: GO-MATH-RAND
import "math/rand/v2"

func Nonce() uint64 {
	return rand.Uint64()
}
