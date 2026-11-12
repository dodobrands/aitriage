package extract

import (
	"archive/tar"
	"fmt"
	"path/filepath"
)

// containsDotDot is defined in another file of the package.
func Target(dest string, hdr *tar.Header) (string, error) {
	if containsDotDot(hdr.Name) {
		return "", fmt.Errorf("unsafe entry %q", hdr.Name)
	}
	return filepath.Join(dest, hdr.Name), nil
}
