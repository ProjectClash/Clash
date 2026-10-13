package cidr

import (
	"bytes"
	"math/rand"
	"net/netip"
	"testing"
	"unsafe"
)

func alignedCopy(data []byte) []byte {
	if len(data) == 0 {
		return []byte{}
	}
	words := make([]uint64, (len(data)+7)/8)
	out := unsafe.Slice((*byte)(unsafe.Pointer(&words[0])), len(data))
	copy(out, data)
	return out
}

func randomPrefix(rng *rand.Rand) netip.Prefix {
	if rng.Intn(3) == 0 {
		var a [16]byte
		rng.Read(a[:])
		return netip.PrefixFrom(netip.AddrFrom16(a), 16+rng.Intn(113)).Masked()
	}
	var a [4]byte
	rng.Read(a[:])
	return netip.PrefixFrom(netip.AddrFrom4(a), 8+rng.Intn(25)).Masked()
}

func TestAMappedIPSetMatchesAsTheSetItWasWrittenFrom(t *testing.T) {
	rng := rand.New(rand.NewSource(11))
	set := NewIpCidrSet()
	var prefixes []netip.Prefix
	for i := 0; i < 20000; i++ {
		prefix := randomPrefix(rng)
		prefixes = append(prefixes, prefix)
		if err := set.AddIpCidr(prefix); err != nil {
			t.Fatal(err)
		}
	}
	for _, special := range []string{"::ffff:0:0/96", "::ffff:10.0.0.0/104", "64:ff9b::/96"} {
		prefix := netip.MustParsePrefix(special)
		prefixes = append(prefixes, prefix)
		_ = set.AddIpCidr(prefix)
	}
	if err := set.Merge(); err != nil {
		t.Fatal(err)
	}
	var buffer bytes.Buffer
	if err := set.WriteMapped(&buffer); err != nil {
		t.Fatal(err)
	}
	mapped, err := OpenMappedIpCidrSet(alignedCopy(buffer.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	var probes []netip.Addr
	for _, prefix := range prefixes {
		first := prefix.Addr()
		probes = append(probes, first, first.Prev(), first.Next())
		last := first
		for i := 0; i < 3 && last.IsValid(); i++ {
			last = last.Next()
		}
	}
	set.Foreach(func(prefix netip.Prefix) bool {
		probes = append(probes, prefix.Addr(), prefix.Addr().Prev())
		return true
	})
	for i := 0; i < 20000; i++ {
		var a4 [4]byte
		rng.Read(a4[:])
		var a16 [16]byte
		rng.Read(a16[:])
		probes = append(probes, netip.AddrFrom4(a4), netip.AddrFrom16(a16), netip.AddrFrom16(netip.AddrFrom4(a4).As16()))
	}
	for _, probe := range probes {
		if !probe.IsValid() {
			continue
		}
		if got, want := mapped.MatchIp(probe), set.MatchIp(probe); got != want {
			t.Fatalf("%s: mapped %v, set %v", probe, got, want)
		}
	}
	if (&MappedIpCidrSet{}).MatchIp(netip.MustParseAddr("1.1.1.1")) {
		t.Fatal("an empty mapped set matched")
	}
}

func TestAMappedIPSetRefusesBytesThatAreNotOne(t *testing.T) {
	set := NewIpCidrSet()
	for _, prefix := range []string{"10.0.0.0/8", "192.168.0.0/16", "2001:db8::/32"} {
		_ = set.AddIpCidrForString(prefix)
	}
	_ = set.Merge()
	var buffer bytes.Buffer
	if err := set.WriteMapped(&buffer); err != nil {
		t.Fatal(err)
	}
	whole := buffer.Bytes()
	for _, cut := range []int{0, 4, 16, len(whole) / 2, len(whole) - 1} {
		if _, err := OpenMappedIpCidrSet(alignedCopy(whole[:cut])); err == nil {
			t.Fatalf("a set cut to %d of %d bytes opened", cut, len(whole))
		}
	}
	for _, at := range []int{0, 9, 20, len(whole) / 2, len(whole) - 1} {
		changed := append([]byte(nil), whole...)
		changed[at] ^= 0x40
		if _, err := OpenMappedIpCidrSet(alignedCopy(changed)); err == nil {
			t.Fatalf("a set with byte %d changed opened", at)
		}
	}
}
