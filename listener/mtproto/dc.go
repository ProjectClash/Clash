package mtproto

import (
	"net/netip"
	"sync/atomic"
)

const maxFamilyEndpoints = 32

type dcFamily struct {
	general []netip.AddrPort
	media   []netip.AddrPort
	failed atomic.Uint32
}

type dataCenter struct {
	v4, v6 dcFamily
}

var productionDCs = [...]dataCenter{
	{
		v4: dcFamily{general: []netip.AddrPort{ep("149.154.175.54"), ep("149.154.175.50")}},
		v6: dcFamily{general: []netip.AddrPort{ep("2001:b28:f23d:f001::a")}},
	},
	{
		v4: dcFamily{
			general: []netip.AddrPort{ep("149.154.167.41"), ep("149.154.167.50"), ep("149.154.167.51"), ep("95.161.76.100")},
			media:   []netip.AddrPort{ep("149.154.167.222")},
		},
		v6: dcFamily{
			general: []netip.AddrPort{ep("2001:67c:4e8:f002::a")},
			media:   []netip.AddrPort{ep("2001:67c:4e8:f002::b")},
		},
	},
	{
		v4: dcFamily{general: []netip.AddrPort{ep("149.154.175.100")}},
		v6: dcFamily{general: []netip.AddrPort{ep("2001:b28:f23d:f003::a")}},
	},
	{
		v4: dcFamily{
			general: []netip.AddrPort{ep("149.154.167.92"), ep("149.154.167.91")},
			media:   []netip.AddrPort{ep("149.154.165.111")},
		},
		v6: dcFamily{
			general: []netip.AddrPort{ep("2001:67c:4e8:f004::a")},
			media:   []netip.AddrPort{ep("2001:67c:4e8:f004::b")},
		},
	},
	{
		v4: dcFamily{general: []netip.AddrPort{ep("91.108.56.191"), ep("149.154.171.5")}},
		v6: dcFamily{general: []netip.AddrPort{ep("2001:b28:f23f:f005::a")}},
	},
}

func ep(ip string) netip.AddrPort {
	return netip.AddrPortFrom(netip.MustParseAddr(ip), 443)
}

var dcTableOverride atomic.Pointer[[]dataCenter]

func dcTable() []dataCenter {
	if table := dcTableOverride.Load(); table != nil {
		return *table
	}
	return productionDCs[:]
}

type dcPick struct {
	addr   netip.AddrPort
	family *dcFamily
	bit    uint32
}

func pickEndpoint(id int16, ipv6 bool) (dcPick, bool) {
	n, media := int(id), id < 0
	if media {
		n = -n
	}
	table := dcTable()
	if n < 1 || n > len(table) {
		return dcPick{}, false
	}
	family := &table[n-1].v4
	if ipv6 {
		family = &table[n-1].v6
	}

	var order [maxFamilyEndpoints]uint8
	count := 0
	general := len(family.general)
	if media {
		for i := range family.media {
			if general+i < maxFamilyEndpoints {
				order[count] = uint8(general + i)
				count++
			}
		}
	}
	for i := 0; i < general && i < maxFamilyEndpoints; i++ {
		order[count] = uint8(i)
		count++
	}
	if count == 0 {
		return dcPick{}, false
	}

	failed := family.failed.Load()
	chosen := order[0]
	for _, bit := range order[:count] {
		if failed&(1<<bit) == 0 {
			return family.at(bit), true
		}
	}
	family.failed.Store(0)
	return family.at(chosen), true
}

func (f *dcFamily) at(bit uint8) dcPick {
	p := dcPick{family: f, bit: uint32(bit)}
	if i := int(bit); i < len(f.general) {
		p.addr = f.general[i]
	} else {
		p.addr = f.media[i-len(f.general)]
	}
	return p
}

func (p dcPick) markFailed() {
	if p.family == nil {
		return
	}
	for {
		old := p.family.failed.Load()
		if old&(1<<p.bit) != 0 || p.family.failed.CompareAndSwap(old, old|1<<p.bit) {
			return
		}
	}
}
