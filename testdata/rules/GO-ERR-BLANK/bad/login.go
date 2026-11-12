package auth

import "golang.org/x/crypto/bcrypt"

func Login(hash, password []byte) bool {
	// ruleid: GO-ERR-BLANK
	_ = bcrypt.CompareHashAndPassword(hash, password)
	return true
}
