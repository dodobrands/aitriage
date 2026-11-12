package files

import "os"

func Open(name string) (*os.File, error) {
	// ruleid: GO-PATH-TRAVERSAL
	return os.Open("/var/data/" + name)
}
