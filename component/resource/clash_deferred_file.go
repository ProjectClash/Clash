package resource

import (
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
)

var deferredFileDirectory atomic.Pointer[string]

func SetDeferredFileDirectory(directory string) {
	if directory == "" {
		deferredFileDirectory.Store(nil)
		return
	}
	cleaned := filepath.Clean(directory)
	deferredFileDirectory.Store(&cleaned)
}

func clashDeferredFile(path string) bool {
	directory := deferredFileDirectory.Load()
	if directory == nil {
		return false
	}
	relative, err := filepath.Rel(*directory, filepath.Clean(path))
	if err != nil || relative == "." || strings.HasPrefix(relative, "..") || filepath.IsAbs(relative) {
		return false
	}
	_, err = os.Lstat(path)
	return os.IsNotExist(err)
}
