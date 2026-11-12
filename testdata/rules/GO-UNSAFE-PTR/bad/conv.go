package conv

import "unsafe"

func String(b []byte) string {
	// ruleid: GO-UNSAFE-PTR
	return *(*string)(unsafe.Pointer(&b))
}
