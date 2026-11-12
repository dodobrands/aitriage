package extract

import (
	"archive/zip"
	"fmt"
	"path/filepath"
)

func Targets(src, dest string) ([]string, error) {
	r, err := zip.OpenReader(src)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	var out []string
	for _, f := range r.File {
		if !filepath.IsLocal(f.Name) {
			return nil, fmt.Errorf("unsafe entry %q", f.Name)
		}
		out = append(out, filepath.Join(dest, f.Name))
	}
	return out, nil
}
