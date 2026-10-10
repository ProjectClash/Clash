package route

import http "github.com/metacubex/http"

type clashUserspaceFileSystem struct{ inner http.FileSystem }

func (fsys clashUserspaceFileSystem) Open(name string) (http.File, error) {
	file, err := fsys.inner.Open(name)
	if err != nil {
		return nil, err
	}
	return clashUserspaceFile{file}, nil
}

type clashUserspaceFile struct{ http.File }
