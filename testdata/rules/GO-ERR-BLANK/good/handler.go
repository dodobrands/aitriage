package api

import (
	"crypto/rand"
	"encoding/json"
	"net/http"
	"os"
)

func Write(w http.ResponseWriter, v any) {
	_ = json.NewEncoder(w).Encode(v)
	_, _ = w.Write([]byte("\n"))
}

func Cleanup(path string) {
	_ = os.Remove(path)
}

func Key(b []byte) error {
	if _, err := rand.Read(b); err != nil {
		return err
	}
	return nil
}
