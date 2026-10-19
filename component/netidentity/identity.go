package netidentity

import (
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
)

const (
	KindWiFi     = "WIFI"
	KindWired    = "WIRED"
	KindCellular = "CELLULAR"
)

type Identity struct {
	Kind string
	Routers []netip.Addr
	SSID  string
	BSSID string
	Radio string
	MCCMNC string
}

var current atomic.Pointer[Identity]

func Current() Identity {
	if id := current.Load(); id != nil {
		return *id
	}
	return Identity{}
}

func Set(id Identity) bool {
	id.Kind = strings.ToUpper(strings.TrimSpace(id.Kind))
	id.SSID = strings.TrimSpace(id.SSID)
	id.BSSID = strings.ToLower(strings.TrimSpace(id.BSSID))
	id.Radio = strings.TrimPrefix(strings.TrimSpace(id.Radio), "CTRadioAccessTechnology")
	id.MCCMNC = strings.TrimSpace(id.MCCMNC)
	if previous := current.Load(); previous != nil && previous.equal(id) {
		return false
	}
	current.Store(&id)
	return true
}

func (id *Identity) equal(other Identity) bool {
	return id.Kind == other.Kind && id.SSID == other.SSID && id.BSSID == other.BSSID &&
		id.Radio == other.Radio && id.MCCMNC == other.MCCMNC && slices.Equal(id.Routers, other.Routers)
}

func Reset() { current.Store(nil) }
