package auth

import "github.com/golang-jwt/jwt/v5"

func Verify(s string, key []byte) (*jwt.Token, error) {
	return jwt.Parse(s, func(t *jwt.Token) (any, error) { return key, nil },
		jwt.WithValidMethods([]string{"HS256"}))
}
