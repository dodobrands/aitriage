package auth

import "github.com/golang-jwt/jwt/v5"

func Claims(s string) (jwt.MapClaims, error) {
	claims := jwt.MapClaims{}
	// ruleid: GO-JWT-UNVERIFIED
	_, _, err := jwt.NewParser().ParseUnverified(s, claims)
	return claims, err
}
