package config

import (
	"encoding/hex"
	"errors"
	"fmt"
	"sort"

	"github.com/ProjectClash/Clash/adapter"
	"github.com/ProjectClash/Clash/adapter/outbound"
	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/log"
	T "github.com/ProjectClash/Clash/tunnel"
)

type ClashNodeLibraryRef struct {
	Path   string `yaml:"path" json:"path"`
	SHA256 string `yaml:"sha256" json:"sha256"`
	InlineAt []int `yaml:"inline-at" json:"inline-at"`
}

var ErrNodeLibraryUnavailable = errors.New("x-clash-node-library: the node library is not here; publish the configuration again")

func clashLibraryNodes(cfg *RawConfig) (*adapter.LibraryNodes, error) {
	ref := cfg.ClashNodeLibrary
	if ref.Path == "" && ref.SHA256 == "" {
		return nil, nil
	}
	sum, err := hex.DecodeString(ref.SHA256)
	if err != nil || len(sum) != 32 || ref.Path == "" {
		return nil, fmt.Errorf("x-clash-node-library: a path and a SHA-256 are required")
	}
	library, err := outbound.OpenNodeLibraryFile(ref.Path, [32]byte(sum))
	if err != nil {
		return nil, fmt.Errorf("%w (%v)", ErrNodeLibraryUnavailable, err)
	}
	return adapter.NewLibraryNodes(library, adapter.WithTunnelForAPI(T.Tunnel)), nil
}

type clashNodeViews struct {
	library *adapter.LibraryNodes
	written C.ProxyList
	sorted  C.ProxyList
	inlineSorted   []C.Proxy
	inlineSortedAt []int
}

func newClashNodes(ref ClashNodeLibraryRef, inline []C.Proxy, library *adapter.LibraryNodes) (*clashNodeViews, error) {
	total := len(inline) + library.Len()
	writtenAt := ref.InlineAt
	if problem := inlinePlacesProblem(writtenAt, len(inline), total); problem != "" {
		if len(writtenAt) > 0 {
			log.Warnln("[Config] x-clash-node-library: %s; the inline proxies are listed first", problem)
		}
		writtenAt = make([]int, len(inline))
		for i := range writtenAt {
			writtenAt[i] = i
		}
	}
	byName := append([]C.Proxy(nil), inline...)
	sort.Slice(byName, func(i, j int) bool { return byName[i].Name() < byName[j].Name() })
	sortedAt := make([]int, len(byName))
	for j, proxy := range byName {
		sortedAt[j] = j + library.Rank(proxy.Name())
	}
	return &clashNodeViews{
		library:        library,
		written:        &insertedProxyList{base: library, at: writtenAt, inserted: inline},
		sorted:         &insertedProxyList{base: library.Sorted(), at: sortedAt, inserted: byName},
		inlineSorted:   byName,
		inlineSortedAt: sortedAt,
	}, nil
}

type insertedProxyList struct {
	base     C.ProxyList
	at       []int
	inserted []C.Proxy
}

func (l *insertedProxyList) Len() int { return l.base.Len() + len(l.inserted) }

func (l *insertedProxyList) At(k int) C.Proxy {
	j := sort.SearchInts(l.at, k)
	if j < len(l.at) && l.at[j] == k {
		return l.inserted[j]
	}
	return l.base.At(k - j)
}

func hasProxy(proxies map[string]C.Proxy, library C.ProxyLibrary, name string) bool {
	if _, ok := proxies[name]; ok {
		return true
	}
	if library != nil {
		_, ok := library.Lookup(name)
		return ok
	}
	return false
}

func clashInternalPositions(nodes *clashNodeViews, internal map[string]struct{}) []int {
	if len(internal) == 0 {
		return nil
	}
	var positions []int
	for j, proxy := range nodes.inlineSorted {
		if _, ok := internal[proxy.Name()]; ok {
			positions = append(positions, nodes.inlineSortedAt[j])
		}
	}
	return positions
}

func inlinePlacesProblem(at []int, count, total int) string {
	if len(at) != count {
		return fmt.Sprintf("%d inline places for %d inline proxies", len(at), count)
	}
	for i, place := range at {
		if place < 0 || place >= total || (i > 0 && place <= at[i-1]) {
			return fmt.Sprintf("inline place %d is out of range or out of order", place)
		}
	}
	return ""
}
