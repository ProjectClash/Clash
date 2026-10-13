package provider

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"math/bits"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"unsafe"

	"github.com/ProjectClash/Clash/component/cidr"

	C "github.com/ProjectClash/Clash/constant"
	P "github.com/ProjectClash/Clash/constant/provider"
	"github.com/ProjectClash/Clash/rules/common"
)

const (
	clashClassicalIndexMagic = "HKCSIDX1"
	clashClassicalIndexVersion = 2
	clashClassicalIndexHeader  = 8 + 9*4
	clashClassicalIndexChecksumAt = 8 + 8*4
	clashClassicalNameEntry       = 12
	ClashClassicalIndexStubType = "CLASH-CLASSICAL-INDEX"
	ClashClassicalIndexStubSuffix = ".stub"
)

func ClashClassicalIndexStub(indexName string, checksum uint32, sourceName string, format P.RuleFormat) string {
	name := "text"
	if format == P.YamlRule {
		name = "yaml"
	}
	return fmt.Sprintf("%s,%s,%08x,%s,%s", ClashClassicalIndexStubType, url.PathEscape(indexName), checksum, url.PathEscape(sourceName), name)
}

func ClashClassicalIndexChecksumOf(path string, whole bool) (uint32, bool) {
	if info, err := os.Lstat(path); err != nil || !info.Mode().IsRegular() || info.Size() > 1<<31 {
		return 0, false
	}
	var data []byte
	if whole {
		read, err := os.ReadFile(path)
		if err != nil {
			return 0, false
		}
		if _, _, _, _, err := readClassicalIndex(read); err != nil {
			return 0, false
		}
		data = read
	} else {
		file, err := os.Open(path)
		if err != nil {
			return 0, false
		}
		defer file.Close()
		data = make([]byte, clashClassicalIndexHeader)
		if _, err := io.ReadFull(file, data); err != nil || string(data[:8]) != clashClassicalIndexMagic ||
			!clashClassicalIndexVersionRead(binary.LittleEndian.Uint32(data[8:])) {
			return 0, false
		}
	}
	return binary.LittleEndian.Uint32(data[clashClassicalIndexChecksumAt:]), true
}

func clashClassicalIndexDirectory(vehicle P.Vehicle) string {
	if vehicle == nil || vehicle.Type() != P.File || !strings.HasSuffix(vehicle.Path(), ClashClassicalIndexStubSuffix) {
		return ""
	}
	if info, err := os.Lstat(vehicle.Path()); err != nil || !info.Mode().IsRegular() {
		return ""
	}
	return filepath.Dir(vehicle.Path())
}

func ClashClassicalLines(buf []byte, format P.RuleFormat) ([]string, error) {
	collector := &classicalLineCollector{}
	if _, err := rulesParse(buf, collector, format); err != nil {
		return nil, err
	}
	return collector.lines, nil
}

type classicalLineCollector struct{ lines []string }

func (c *classicalLineCollector) Behavior() P.RuleBehavior                  { return P.Classical }
func (c *classicalLineCollector) Match(*C.Metadata, C.RuleMatchHelper) bool { return false }
func (c *classicalLineCollector) Count() int                                { return len(c.lines) }
func (c *classicalLineCollector) Reset()                                    { c.lines = nil }
func (c *classicalLineCollector) Insert(rule string)                        { c.lines = append(c.lines, rule) }
func (c *classicalLineCollector) FinishInsert()                             {}

type ClashClassicalIndex struct {
	Bytes []byte
	Rules int
	Names int
	IPRules int
	Checksum uint32
}

func ClashCompileClassicalIndex(lines []string, parse common.ParseRuleFunc) (ClashClassicalIndex, error) {
	s := NewClassicalStrategy(parse)
	s.keepText = true
	for _, line := range lines {
		s.Insert(line)
	}
	if s.heavy != nil {
		return ClashClassicalIndex{}, s.heavy
	}
	if s.mapped != nil {
		return ClashClassicalIndex{}, errors.New("a compiled index cannot be compiled again")
	}
	var domains, suffixes int
	pool := 0
	for _, name := range s.names {
		if name.suffix {
			suffixes++
		} else {
			domains++
		}
		if len(name.name) > 0xffff {
			return ClashClassicalIndex{}, fmt.Errorf("a name of %d bytes", len(name.name))
		}
		pool += len(name.name)
	}
	kept, ipRuns, err := clashClassicalIPRuns(s.others)
	if err != nil {
		return ClashClassicalIndex{}, err
	}
	s.others = kept
	if len(kept)+s.children > ClashClassicalOthersLimit {
		return ClashClassicalIndex{}, fmt.Errorf("%w: more than %d rules that are neither a domain nor an IP range in one set, counting the rules inside logic rules, so it loads no rules", ErrClassicalTooHeavy, ClashClassicalOthersLimit)
	}
	if len(ipRuns) > ClashClassicalIPRunLimit {
		return ClashClassicalIndex{}, fmt.Errorf("%w: its IP rules change kind more than %d times, so it loads no rules", ErrClassicalTooHeavy, ClashClassicalIPRunLimit)
	}
	ipRules := 0
	for _, run := range ipRuns {
		ipRules += run.rules
	}
	ipSection := clashClassicalIPSectionSize(ipRuns)
	othersBytes := 0
	for _, other := range s.others {
		othersBytes += 8 + len(other.text)
	}
	domainSlots, suffixSlots := classicalIndexSlots(domains), classicalIndexSlots(suffixes)
	size := clashClassicalIndexHeader + len(s.names)*clashClassicalNameEntry + 4*(domainSlots+suffixSlots) + align4(pool) + othersBytes
	out := make([]byte, size+ipSection)
	copy(out, clashClassicalIndexMagic)
	le := binary.LittleEndian
	header := []int{clashClassicalIndexVersion, s.count, len(s.names), len(s.others), domainSlots, suffixSlots, pool, othersBytes}
	for i, value := range header {
		le.PutUint32(out[8+4*i:], uint32(value))
	}
	at := clashClassicalIndexHeader
	poolAt := at + len(s.names)*clashClassicalNameEntry + 4*(domainSlots+suffixSlots)
	offset := 0
	for _, name := range s.names {
		le.PutUint32(out[at:], uint32(offset))
		le.PutUint16(out[at+4:], uint16(len(name.name)))
		if name.suffix {
			out[at+6] = 1
		}
		le.PutUint32(out[at+8:], uint32(name.line))
		copy(out[poolAt+offset:], name.name)
		offset += len(name.name)
		at += clashClassicalNameEntry
	}
	domainAt := at
	suffixAt := at + 4*domainSlots
	for i, name := range s.names {
		slotsAt, slots := domainAt, domainSlots
		if name.suffix {
			slotsAt, slots = suffixAt, suffixSlots
		}
		mask := uint64(slots - 1)
		for h := clashClassicalHash(name.name) & mask; ; h = (h + 1) & mask {
			slot := le.Uint32(out[slotsAt+4*int(h):])
			if slot == 0 {
				le.PutUint32(out[slotsAt+4*int(h):], uint32(i+1))
				break
			}
			if s.names[slot-1].name == name.name {
				break
			}
		}
	}
	at = poolAt + align4(pool)
	for _, other := range s.others {
		le.PutUint32(out[at:], uint32(other.line))
		le.PutUint32(out[at+4:], uint32(len(other.text)))
		copy(out[at+8:], other.text)
		at += 8 + len(other.text)
	}
	writeClashClassicalIPSection(out[at:], ipRuns)
	checksum := clashClassicalIndexChecksum(out)
	le.PutUint32(out[clashClassicalIndexChecksumAt:], checksum)
	return ClashClassicalIndex{Bytes: out, Rules: s.count, Names: len(s.names), IPRules: ipRules, Checksum: checksum}, nil
}

func clashClassicalIndexChecksum(data []byte) uint32 {
	return crc32.Update(crc32.ChecksumIEEE(data[8:clashClassicalIndexChecksumAt]), crc32.IEEETable, data[clashClassicalIndexHeader:])
}

func classicalIndexSlots(n int) int {
	if n == 0 {
		return 0
	}
	size := 8
	for size < n+n/4 {
		size <<= 1
	}
	return size
}

func align4(n int) int { return (n + 3) &^ 3 }

func clashClassicalHash(s string) uint64 {
	const (
		p0 = 0xa0761d6478bd642f
		p1 = 0xe7037ed1a0b428db
		p2 = 0x8ebc6af09c88c6e3
	)
	h := uint64(len(s)) ^ p0
	for ; len(s) >= 8; s = s[8:] {
		h = clashClassicalMix(h^p1, clashClassicalWord(s)^p2)
	}
	var tail uint64
	for i := 0; i < len(s); i++ {
		tail |= uint64(s[i]) << (8 * i)
	}
	return clashClassicalMix(h^p2, tail^p1)
}

func clashClassicalMix(a, b uint64) uint64 {
	hi, lo := bits.Mul64(a, b)
	return hi ^ lo
}

func clashClassicalWord(s string) uint64 {
	return uint64(s[0]) | uint64(s[1])<<8 | uint64(s[2])<<16 | uint64(s[3])<<24 |
		uint64(s[4])<<32 | uint64(s[5])<<40 | uint64(s[6])<<48 | uint64(s[7])<<56
}

type classicalMapped struct {
	data                   []byte
	names                  []byte
	domains, suffixes      []byte
	domainMask, suffixMask uint64
	pool                   []byte
}

func loadClassicalIndex(path string, want uint32) (*classicalMapped, int, []classicalOther, []classicalIPStep, error) {
	if info, err := os.Lstat(path); err != nil {
		return nil, 0, nil, nil, err
	} else if !info.Mode().IsRegular() {
		return nil, 0, nil, nil, errors.New("not a regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, 0, nil, nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, 0, nil, nil, err
	}
	if info.Size() < clashClassicalIndexHeader || info.Size() > 1<<31 {
		return nil, 0, nil, nil, fmt.Errorf("an index of %d bytes", info.Size())
	}
	data, err := mapClassicalIndex(file, int(info.Size()))
	if err != nil {
		return nil, 0, nil, nil, err
	}
	m, names, others, ipSteps, err := readClassicalIndex(data)
	if err == nil && binary.LittleEndian.Uint32(data[clashClassicalIndexChecksumAt:]) != want {
		err = errors.New("not the index its stub names")
	}
	if err != nil {
		unmapClassicalIndex(data)
		return nil, 0, nil, nil, err
	}
	runtime.AddCleanup(m, unmapClassicalIndex, data)
	return m, names, others, ipSteps, nil
}

type classicalOther struct {
	line int32
	text string
}

func readClassicalIndex(data []byte) (*classicalMapped, int, []classicalOther, []classicalIPStep, error) {
	if len(data) < clashClassicalIndexHeader || string(data[:8]) != clashClassicalIndexMagic {
		return nil, 0, nil, nil, errors.New("not a classical index")
	}
	le := binary.LittleEndian
	field := func(i int) int { return int(le.Uint32(data[8+4*i:])) }
	version := field(0)
	if !clashClassicalIndexVersionRead(uint32(version)) {
		return nil, 0, nil, nil, fmt.Errorf("index version %d", version)
	}
	count, names, others := field(1), field(2), field(3)
	domainSlots, suffixSlots, pool, othersBytes := field(4), field(5), field(6), field(7)
	if clashClassicalIndexChecksum(data) != uint32(field(8)) {
		return nil, 0, nil, nil, errors.New("index checksum")
	}
	if others > ClashClassicalOthersLimit {
		return nil, 0, nil, nil, fmt.Errorf("%d lines parsed at load, more than %d", others, ClashClassicalOthersLimit)
	}
	if others < 0 || others > othersBytes/8 {
		return nil, 0, nil, nil, errors.New("more other lines than their bytes hold")
	}
	for _, slots := range []int{domainSlots, suffixSlots} {
		if slots != 0 && (slots < 8 || slots&(slots-1) != 0) {
			return nil, 0, nil, nil, fmt.Errorf("%d slots", slots)
		}
	}
	size := clashClassicalIndexHeader + names*clashClassicalNameEntry + 4*(domainSlots+suffixSlots) + align4(pool) + othersBytes
	if names < 0 || count < names || size > len(data) || (version == 1 && (count > names+others || size != len(data))) {
		return nil, 0, nil, nil, errors.New("index sections do not add up")
	}
	m := &classicalMapped{data: data}
	at := clashClassicalIndexHeader
	m.names = data[at : at+names*clashClassicalNameEntry]
	at += len(m.names)
	m.domains = data[at : at+4*domainSlots]
	at += len(m.domains)
	m.suffixes = data[at : at+4*suffixSlots]
	at += len(m.suffixes)
	m.pool = data[at : at+pool]
	at += align4(pool)
	if domainSlots > 0 {
		m.domainMask = uint64(domainSlots - 1)
	}
	if suffixSlots > 0 {
		m.suffixMask = uint64(suffixSlots - 1)
	}
	for i := 0; i < names; i++ {
		entry := m.names[i*clashClassicalNameEntry:]
		if int(le.Uint32(entry))+int(le.Uint16(entry[4:])) > pool {
			return nil, 0, nil, nil, errors.New("a name outside the pool")
		}
	}
	for _, slots := range [][]byte{m.domains, m.suffixes} {
		empty := false
		for i := 0; i+4 <= len(slots); i += 4 {
			slot := int(le.Uint32(slots[i:]))
			if slot > names {
				return nil, 0, nil, nil, errors.New("a slot outside the names")
			}
			empty = empty || slot == 0
		}
		if len(slots) > 0 && !empty {
			return nil, 0, nil, nil, errors.New("a table with no empty slot")
		}
	}
	list := make([]classicalOther, 0, others)
	for i := 0; i < others; i++ {
		if at+8 > len(data) {
			return nil, 0, nil, nil, errors.New("an other line outside the index")
		}
		line, length := int32(le.Uint32(data[at:])), int(le.Uint32(data[at+4:]))
		if at+8+length > len(data) {
			return nil, 0, nil, nil, errors.New("an other line outside the index")
		}
		list = append(list, classicalOther{line: line, text: string(data[at+8 : at+8+length])})
		at += 8 + length
	}
	if version == 1 {
		return m, names, list, nil, nil
	}
	steps, ipRules, end, err := readClassicalIPSteps(data, at)
	if err != nil {
		return nil, 0, nil, nil, err
	}
	if end != len(data) || count > names+others+ipRules {
		return nil, 0, nil, nil, errors.New("index sections do not add up")
	}
	return m, names, list, steps, nil
}

func (m *classicalMapped) find(name string, suffix bool) (int32, bool) {
	slots, mask := m.domains, m.domainMask
	if suffix {
		slots, mask = m.suffixes, m.suffixMask
	}
	if len(slots) == 0 {
		return 0, false
	}
	le := binary.LittleEndian
	for h, probes := clashClassicalHash(name)&mask, len(slots)/4; probes > 0; h, probes = (h+1)&mask, probes-1 {
		slot := int(le.Uint32(slots[4*h:]))
		if slot == 0 {
			return 0, false
		}
		at := (slot - 1) * clashClassicalNameEntry
		if at+clashClassicalNameEntry > len(m.names) {
			return 0, false
		}
		entry := m.names[at:]
		offset, length := int(le.Uint32(entry)), int(le.Uint16(entry[4:]))
		if length == len(name) && offset+length <= len(m.pool) &&
			unsafe.String(unsafe.SliceData(m.pool[offset:]), length) == name {
			return int32(le.Uint32(entry[8:])), true
		}
	}
	return 0, false
}

func parseClassicalIndexStub(line, directory string) (index string, checksum uint32, source string, format P.RuleFormat, ok bool) {
	fields := strings.Split(strings.TrimSpace(line), ",")
	if len(fields) != 5 || fields[0] != ClashClassicalIndexStubType || len(fields[2]) != 8 {
		return "", 0, "", 0, false
	}
	index, err1 := url.PathUnescape(fields[1])
	sum, err2 := strconv.ParseUint(fields[2], 16, 32)
	source, err3 := url.PathUnescape(fields[3])
	format, err4 := P.ParseRuleFormat(fields[4])
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil || !plainFileName(index) || !plainFileName(source) ||
		fields[4] == "" || format == P.MrsRule {
		return "", 0, "", 0, false
	}
	return filepath.Join(directory, index), uint32(sum), filepath.Join(directory, source), format, true
}

func plainFileName(name string) bool {
	return name != "" && name != "." && name != ".." && !strings.ContainsAny(name, `/\`) && filepath.Base(name) == name
}

func clashClassicalIndexVersionRead(version uint32) bool { return version == 1 || version == 2 }

type classicalIPStep struct {
	line            int
	source, resolve bool
	rules           int
	set             *cidr.MappedIpCidrSet
}

type clashClassicalIPRun struct {
	line            int32
	source, resolve bool
	rules           int
	set             []byte
}

func clashClassicalIPRuns(others []classicalRule) ([]classicalRule, []clashClassicalIPRun, error) {
	var kept []classicalRule
	var runs []clashClassicalIPRun
	var current *cidr.IpCidrSet
	var run clashClassicalIPRun
	flush := func() error {
		if current == nil {
			return nil
		}
		var b bytes.Buffer
		if err := current.WriteMapped(&b); err != nil {
			return err
		}
		run.set = b.Bytes()
		runs = append(runs, run)
		current = nil
		return nil
	}
	for _, other := range others {
		r, ok := other.rule.(*common.IPCIDR)
		var prefix netip.Prefix
		var err error
		if ok {
			prefix, err = netip.ParsePrefix(r.Payload())
		}
		if !ok || err != nil {
			if err := flush(); err != nil {
				return nil, nil, err
			}
			kept = append(kept, other)
			continue
		}
		source, resolve := r.ClashIsSourceIP(), r.ClashResolvesIP()
		if current == nil || run.source != source || run.resolve != resolve {
			if err := flush(); err != nil {
				return nil, nil, err
			}
			current = cidr.NewIpCidrSet()
			run = clashClassicalIPRun{line: other.line, source: source, resolve: resolve}
		}
		if err := current.AddIpCidr(prefix); err != nil {
			return nil, nil, err
		}
		run.rules++
	}
	if err := flush(); err != nil {
		return nil, nil, err
	}
	return kept, runs, nil
}

func clashClassicalIPSectionSize(runs []clashClassicalIPRun) int {
	size := 4
	for _, run := range runs {
		size += 16 + align4(len(run.set))
	}
	return size
}

func writeClashClassicalIPSection(out []byte, runs []clashClassicalIPRun) {
	le := binary.LittleEndian
	le.PutUint32(out, uint32(len(runs)))
	at := 4
	for _, run := range runs {
		flags := uint32(0)
		if run.source {
			flags |= 1
		}
		if run.resolve {
			flags |= 2
		}
		le.PutUint32(out[at:], uint32(run.line))
		le.PutUint32(out[at+4:], flags)
		le.PutUint32(out[at+8:], uint32(run.rules))
		le.PutUint32(out[at+12:], uint32(len(run.set)))
		copy(out[at+16:], run.set)
		at += 16 + align4(len(run.set))
	}
}

func readClassicalIPSteps(data []byte, at int) ([]classicalIPStep, int, int, error) {
	le := binary.LittleEndian
	if at+4 > len(data) {
		return nil, 0, 0, errors.New("an IP section outside the index")
	}
	n := int(le.Uint32(data[at:]))
	at += 4
	if n > (len(data)-at)/16 {
		return nil, 0, 0, errors.New("more IP runs than their bytes hold")
	}
	if n > ClashClassicalIPRunLimit {
		return nil, 0, 0, fmt.Errorf("%d IP runs, more than %d", n, ClashClassicalIPRunLimit)
	}
	steps := make([]classicalIPStep, 0, n)
	rules := 0
	for i := 0; i < n; i++ {
		if at+16 > len(data) {
			return nil, 0, 0, errors.New("an IP run outside the index")
		}
		line, flags, count, length := int(le.Uint32(data[at:])), le.Uint32(data[at+4:]), int(le.Uint32(data[at+8:])), int(le.Uint32(data[at+12:]))
		if length < 0 || at+16+length > len(data) || count < 1 {
			return nil, 0, 0, errors.New("an IP run outside the index")
		}
		set, err := cidr.OpenMappedIpCidrSet(data[at+16 : at+16+length])
		if err != nil {
			return nil, 0, 0, err
		}
		steps = append(steps, classicalIPStep{line: line, source: flags&1 != 0, resolve: flags&2 != 0, rules: count, set: set})
		rules += count
		at += 16 + align4(length)
	}
	return steps, rules, at, nil
}

func ClashCheckClassicalIndexFile(path string) (uint32, error) {
	if info, err := os.Lstat(path); err != nil {
		return 0, err
	} else if !info.Mode().IsRegular() || info.Size() < clashClassicalIndexHeader || info.Size() > 1<<31 {
		return 0, errors.New("not a classical index")
	}
	file, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return 0, err
	}
	data, err := mapClassicalIndex(file, int(info.Size()))
	if err != nil {
		return 0, err
	}
	defer unmapClassicalIndex(data)
	le := binary.LittleEndian
	if string(data[:8]) != clashClassicalIndexMagic || !clashClassicalIndexVersionRead(le.Uint32(data[8:])) {
		return 0, errors.New("not a classical index of this core")
	}
	checksum := le.Uint32(data[clashClassicalIndexChecksumAt:])
	if clashClassicalIndexChecksum(data) != checksum {
		return 0, errors.New("index checksum")
	}
	return checksum, nil
}
