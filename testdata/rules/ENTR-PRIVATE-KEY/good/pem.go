package keys

import "strings"

func isPKCS1(pemText string) bool {
	return strings.HasPrefix(pemText, "-----BEGIN RSA PRIVATE KEY-----")
}
