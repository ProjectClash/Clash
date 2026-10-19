//go:build !go1.23

package filepath

import (
	"errors"
	"io/fs"
)

var errInvalidPath = errors.New("invalid path")

func Localize(path string) (string, error) {
	if !fs.ValidPath(path) {
		return "", errInvalidPath
	}
	return localize(path)
}
