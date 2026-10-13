package provider

import (
	"encoding/binary"
	"errors"
	"runtime"
	"testing"

	C "github.com/ProjectClash/Clash/constant"
)

func noParse(string, string, string, []string, map[string][]C.Rule) (C.Rule, error) {
	return nil, errors.New("not parsed here")
}

func TestAClassicalIndexWithAFullTableIsRefusedAndCannotHang(t *testing.T) {
	index, err := ClashCompileClassicalIndex([]string{"DOMAIN,a.example", "DOMAIN,b.example", "DOMAIN-SUFFIX,c.example"}, noParse)
	if err != nil {
		t.Fatal(err)
	}
	data := append([]byte(nil), index.Bytes...)
	le := binary.LittleEndian
	names, domainSlots := int(le.Uint32(data[8+4*2:])), int(le.Uint32(data[8+4*4:]))
	slotsAt := clashClassicalIndexHeader + names*clashClassicalNameEntry
	for i := 0; i < domainSlots; i++ {
		le.PutUint32(data[slotsAt+4*i:], 1)
	}
	le.PutUint32(data[clashClassicalIndexChecksumAt:], clashClassicalIndexChecksum(data))
	if _, _, _, _, err := readClassicalIndex(data); err == nil {
		t.Fatal("a full table was accepted")
	}
	m := &classicalMapped{names: data[clashClassicalIndexHeader:slotsAt], domains: data[slotsAt : slotsAt+4*domainSlots],
		domainMask: uint64(domainSlots - 1)}
	if _, found := m.find("absent.example", false); found {
		t.Fatal("an absent name was found")
	}
}

func TestAClassicalIndexChangedAfterItsCheckReadsNothingOutside(t *testing.T) {
	index, err := ClashCompileClassicalIndex([]string{"DOMAIN,a.example", "DOMAIN-SUFFIX,b.example", "IP-CIDR,10.0.0.0/8"}, noParse)
	if err != nil {
		t.Fatal(err)
	}
	data := append([]byte(nil), index.Bytes...)
	m, _, _, _, err := readClassicalIndex(data)
	if err != nil {
		t.Fatal(err)
	}
	le := binary.LittleEndian
	for i := 0; i+4 <= len(m.domains); i += 4 {
		if le.Uint32(m.domains[i:]) != 0 {
			le.PutUint32(m.domains[i:], 1<<30)
		}
	}
	for i := 0; i+clashClassicalNameEntry <= len(m.names); i += clashClassicalNameEntry {
		le.PutUint32(m.names[i:], 1<<30)
	}
	for _, probe := range []struct {
		name   string
		suffix bool
	}{{"a.example", false}, {"b.example", true}, {"x.example", false}} {
		if _, found := m.find(probe.name, probe.suffix); found {
			t.Errorf("%s found through a changed entry", probe.name)
		}
	}
}

func TestAClassicalIndexCountsNoMoreLinesThanItsBytesHold(t *testing.T) {
	index, err := ClashCompileClassicalIndex([]string{"DOMAIN,a.example"}, noParse)
	if err != nil {
		t.Fatal(err)
	}
	data := append([]byte(nil), index.Bytes...)
	binary.LittleEndian.PutUint32(data[8+4*3:], 1<<24)
	binary.LittleEndian.PutUint32(data[clashClassicalIndexChecksumAt:], clashClassicalIndexChecksum(data))
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, _, _, _, err = readClassicalIndex(data)
	runtime.ReadMemStats(&after)
	if err == nil {
		t.Fatal("an index counting more other lines than it holds was read")
	}
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 64<<10 {
		t.Errorf("%d bytes allocated before refusing", allocated)
	}
}

func TestAClassicalIndexHeaderIsUnderItsChecksum(t *testing.T) {
	index, err := ClashCompileClassicalIndex([]string{"DOMAIN,a.example", "IP-CIDR,10.0.0.0/8", "INVALID_RULE,x"}, noParse)
	if err != nil {
		t.Fatal(err)
	}
	data := append([]byte(nil), index.Bytes...)
	if _, _, _, _, err := readClassicalIndex(data); err != nil {
		t.Fatal(err)
	}
	le := binary.LittleEndian
	names, others := le.Uint32(data[8+4*2:]), le.Uint32(data[8+4*3:])
	if count := le.Uint32(data[8+4*1:]); count >= names+others {
		t.Fatalf("fixture: count %d leaves no room below %d", count, names+others)
	}
	le.PutUint32(data[8+4*1:], names+others)
	if _, _, _, _, err := readClassicalIndex(data); err == nil {
		t.Fatal("a changed header was read")
	}
}
