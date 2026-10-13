package cidr

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sort"

	"go4.org/netipx"
)


var mappedIPSetMagic = [4]byte{'C', 'I', 'P', '1'}

const (
	mappedIPSetHeader = 4 + 4 + 8 + 8
	mappedIPSetRecord = 32
)

func (set *IpCidrSet) WriteMapped(w io.Writer) error {
	var builder netipx.IPSetBuilder
	for _, r := range set.rr {
		builder.AddRange(r)
	}
	merged, err := builder.IPSet()
	if err != nil {
		return err
	}
	ranges := merged.Ranges()
	count4 := 0
	for _, r := range ranges {
		if r.From().Is4() {
			count4++
		}
	}
	digest := sha256.New()
	out := io.MultiWriter(w, digest)
	header := make([]byte, mappedIPSetHeader)
	copy(header, mappedIPSetMagic[:])
	binary.LittleEndian.PutUint64(header[8:], uint64(len(ranges)))
	binary.LittleEndian.PutUint64(header[16:], uint64(count4))
	if _, err := out.Write(header); err != nil {
		return err
	}
	record := make([]byte, mappedIPSetRecord)
	for _, r := range ranges {
		from, to := r.From().As16(), r.To().As16()
		copy(record, from[:])
		copy(record[16:], to[:])
		if _, err := out.Write(record); err != nil {
			return err
		}
	}
	_, err = w.Write(digest.Sum(nil))
	return err
}

type MappedIpCidrSet struct {
	records []byte
	count4  int
}

func OpenMappedIpCidrSet(data []byte) (*MappedIpCidrSet, error) {
	if len(data) < mappedIPSetHeader+sha256.Size {
		return nil, fmt.Errorf("a mapped IP set of %d bytes is shorter than its header", len(data))
	}
	if [4]byte(data[:4]) != mappedIPSetMagic {
		return nil, errors.New("not a mapped IP set")
	}
	count, count4 := binary.LittleEndian.Uint64(data[8:]), binary.LittleEndian.Uint64(data[16:])
	if count4 > count || count > uint64(len(data))/mappedIPSetRecord {
		return nil, fmt.Errorf("a mapped IP set's counts %d/%d are out of range", count4, count)
	}
	total := mappedIPSetHeader + int(count)*mappedIPSetRecord
	if total+sha256.Size != len(data) {
		return nil, fmt.Errorf("a mapped IP set's count says %d bytes, the data is %d", total+sha256.Size, len(data))
	}
	if sum := sha256.Sum256(data[:total]); [sha256.Size]byte(data[total:]) != sum {
		return nil, errors.New("a mapped IP set's checksum does not match its bytes")
	}
	set := &MappedIpCidrSet{records: data[mappedIPSetHeader:total], count4: int(count4)}
	n := int(count)
	for i := 0; i < n; i++ {
		from, to := set.from(i), set.to(i)
		is4 := i < set.count4
		if (is4 && (!isV4Mapped(from) || !isV4Mapped(to))) || bytes.Compare(from, to) > 0 {
			return nil, fmt.Errorf("a mapped IP set's range %d is not a range of its family", i)
		}
		if i > 0 && i != set.count4 && bytes.Compare(set.to(i-1), from) >= 0 {
			return nil, fmt.Errorf("a mapped IP set's ranges %d and %d are out of order", i-1, i)
		}
	}
	return set, nil
}

func (set *MappedIpCidrSet) from(i int) []byte {
	return set.records[i*mappedIPSetRecord : i*mappedIPSetRecord+16]
}

func (set *MappedIpCidrSet) to(i int) []byte {
	return set.records[i*mappedIPSetRecord+16 : (i+1)*mappedIPSetRecord]
}

func (set *MappedIpCidrSet) MatchIp(ip netip.Addr) bool {
	if set == nil || !ip.IsValid() || len(set.records) == 0 {
		return false
	}
	ip = ip.WithZone("")
	low, high := 0, set.count4
	if !ip.Is4() {
		low, high = set.count4, len(set.records)/mappedIPSetRecord
	}
	key := ip.As16()
	i := low + sort.Search(high-low, func(j int) bool { return bytes.Compare(set.to(low+j), key[:]) >= 0 })
	return i < high && bytes.Compare(set.from(i), key[:]) <= 0
}

func isV4Mapped(address []byte) bool {
	for _, b := range address[:10] {
		if b != 0 {
			return false
		}
	}
	return address[10] == 0xff && address[11] == 0xff
}

func (set *MappedIpCidrSet) ToIPSet() *netipx.IPSet {
	var builder netipx.IPSetBuilder
	for i := 0; i < len(set.records)/mappedIPSetRecord; i++ {
		from, to := netip.AddrFrom16([16]byte(set.from(i))), netip.AddrFrom16([16]byte(set.to(i)))
		if i < set.count4 {
			from, to = from.Unmap(), to.Unmap()
		}
		builder.AddRange(netipx.IPRangeFrom(from, to))
	}
	ipSet, _ := builder.IPSet()
	return ipSet
}
