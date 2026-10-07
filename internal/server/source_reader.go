package server

import (
	"fmt"
	"io"
	"os"
)

const maxSourceBytes = 4 << 20

// Source views are bounded and never read devices, directories or named pipes.
func readSourceFile(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("source must be a regular file")
	}
	if info.Size() > maxSourceBytes {
		return nil, fmt.Errorf("source exceeds the 4 MiB preview limit")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxSourceBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxSourceBytes {
		return nil, fmt.Errorf("source exceeds the 4 MiB preview limit")
	}
	return data, nil
}
