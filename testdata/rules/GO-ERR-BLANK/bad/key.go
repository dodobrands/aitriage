package auth

import "crypto/rand"

func Key() []byte {
	b := make([]byte, 32)
	// ruleid: GO-ERR-BLANK
	_, _ = rand.Read(b)
	return b
}
