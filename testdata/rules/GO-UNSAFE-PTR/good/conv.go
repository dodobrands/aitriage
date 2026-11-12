package conv

// String converts without unsafe.Pointer.
func String(b []byte) string {
	return string(b)
}
