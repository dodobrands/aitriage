package extract

import (
	"archive/tar"
	"path"
)

// Joining to "/" first cleans the name into a rooted path.
func Key(hdr *tar.Header) string {
	return path.Join(".", path.Join("/", hdr.Name))
}
