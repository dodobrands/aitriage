package auth

import "os"

func signingKey() []byte {
	if k := os.Getenv("JWT_SECRET"); k != "" {
		return []byte(k)
	}
	// ruleid: ENTR-11
	return []byte("default_secret_key_change_me_in_prod")
}
