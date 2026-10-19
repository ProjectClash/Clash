//go:build !unix

package clashindex

import (
	"io"
	"os"
)

func mapIndex(file *os.File, size int) ([]byte, error) {
	data := make([]byte, size)
	if _, err := io.ReadFull(file, data); err != nil {
		return nil, err
	}
	return data, nil
}

func unmapIndex([]byte) {}

func openIndexFile(path string) (*os.File, error) { return os.Open(path) }
