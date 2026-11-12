package store

import "crypto/md5"

func sum(b []byte) [16]byte {
	// ruleid: ENTR-WEAK-CRYPTO
	return md5.Sum(b)
}
