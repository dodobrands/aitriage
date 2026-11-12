package report

import (
	"crypto/hmac"
	"crypto/sha1"
)

var weakHashClasses = []string{"md5", "sha1", "insecure-hash"}

func sign(key, msg []byte) []byte {
	m := hmac.New(sha1.New, key)
	m.Write(msg)
	return m.Sum(nil)
}
