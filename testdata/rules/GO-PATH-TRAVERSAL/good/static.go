package files

import (
	"os"
	"path/filepath"
)

func OpenConfig() (*os.File, error) {
	return os.Open("/var/data/config.json")
}

func OpenUpload(name string) (*os.File, error) {
	return os.Open("/var/data/uploads/" + filepath.Base(name))
}
