package ca

import (
	"crypto/x509"
	_ "embed"
	"fmt"
	"strings"
)

type Store string

const (
	StoreDefault Store = ""
	StoreSystem  Store = "system"
	StoreMozilla Store = "mozilla"
	StoreChrome  Store = "chrome"
	StoreNone    Store = "none"
)

//go:embed mozilla.pem
var mozillaRoots []byte

//go:embed chrome.pem
var chromeRoots []byte

var selectedStore = StoreDefault

func ParseStore(value string) (Store, error) {
	switch Store(strings.ToLower(strings.TrimSpace(value))) {
	case StoreDefault:
		return StoreDefault, nil
	case StoreSystem:
		return StoreSystem, nil
	case StoreMozilla:
		return StoreMozilla, nil
	case StoreChrome:
		return StoreChrome, nil
	case StoreNone:
		return StoreNone, nil
	default:
		return StoreDefault, fmt.Errorf(
			"unknown certificate store %q; expected %q, %q, %q or %q",
			value, StoreSystem, StoreMozilla, StoreChrome, StoreNone)
	}
}

func SetStore(store Store) {
	mutex.Lock()
	selectedStore = store
	mutex.Unlock()
	ResetCertificate()
}

func SelectedStore() Store {
	mutex.RLock()
	defer mutex.RUnlock()
	return selectedStore
}

func storeRoots(store Store) ([]byte, bool) {
	switch store {
	case StoreMozilla:
		return mozillaRoots, true
	case StoreChrome:
		return chromeRoots, true
	default:
		return nil, false
	}
}

func basePool(store Store) (pool *x509.CertPool, appendEmbedded bool) {
	if roots, bundled := storeRoots(store); bundled {
		pool = x509.NewCertPool()
		pool.AppendCertsFromPEM(roots)
		return pool, false
	}
	if store == StoreNone {
		return x509.NewCertPool(), false
	}
	if DisableSystemCa {
		return x509.NewCertPool(), !DisableEmbedCa
	}
	systemPool, err := x509.SystemCertPool()
	if err != nil {
		systemPool = x509.NewCertPool()
	}
	return systemPool, !DisableEmbedCa
}
