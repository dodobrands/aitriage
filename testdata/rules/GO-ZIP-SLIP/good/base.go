package extract

import (
	"archive/tar"
	"path/filepath"
)

func Target(dest string, hdr *tar.Header) string {
	return filepath.Join(dest, filepath.Base(hdr.Name))
}
