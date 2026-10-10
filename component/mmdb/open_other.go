//go:build !windows

package mmdb

import "github.com/oschwald/maxminddb-golang"

func openDatabaseFile(path string) (*maxminddb.Reader, error) {
	if err := statDatabaseSize(path); err != nil {
		return nil, err
	}
	return maxminddb.Open(path)
}
