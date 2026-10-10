package mmdb

import (
	"errors"
	"fmt"

	"github.com/oschwald/maxminddb-golang"
)

func (r IPReader) NetworkCounts() (map[string]int, bool) {
	return snapshotCounts(r.holder, func(s *snapshot) (map[string]int, error) {
		return countNetworks(s.reader, s.databaseType)
	})
}

func (r ASNReader) NetworkCounts() (map[string]int, bool) {
	return snapshotCounts(r.holder, func(s *snapshot) (map[string]int, error) {
		return countASNNetworks(s.reader)
	})
}

func snapshotCounts(holder *readerHolder, count func(*snapshot) (map[string]int, error)) (map[string]int, bool) {
	if holder == nil {
		return nil, false
	}
	s := holder.acquire()
	if s == nil {
		return nil, false
	}
	defer holder.release(s)
	s.countsOnce.Do(func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				s.counts = nil
			}
		}()
		counts, err := count(s)
		if err == nil {
			s.counts = counts
		}
	})
	return s.counts, s.counts != nil
}

func countNetworks(reader *maxminddb.Reader, kind databaseType) (map[string]int, error) {
	counts := map[string]int{}
	networks := reader.Networks(maxminddb.SkipAliasedNetworks)
	for networks.Next() {
		codes := decodeCodes(kind, func(result any) error {
			_, err := networks.Network(result)
			return err
		})
		for _, code := range codes {
			counts[code]++
		}
	}
	return counts, networks.Err()
}

var errUnsupportedASNType = errors.New("unsupported ASN database type")

func countASNNetworks(reader *maxminddb.Reader) (map[string]int, error) {
	counts := map[string]int{}
	databaseType := reader.Metadata.DatabaseType
	networks := reader.Networks(maxminddb.SkipAliasedNetworks)
	for networks.Next() {
		asn, _, supported := decodeASN(databaseType, func(result any) error {
			_, err := networks.Network(result)
			return err
		})
		if !supported {
			return nil, fmt.Errorf("%w: %s", errUnsupportedASNType, databaseType)
		}
		if asn != "" {
			counts[asn]++
		}
	}
	return counts, networks.Err()
}
