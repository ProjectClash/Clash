//go:build !go1.23 && unix

package filepath

import "strings"

func localize(path string) (string, error) {
	if strings.IndexByte(path, 0) >= 0 {
		return "", errInvalidPath
	}
	return path, nil
}
