package clashindex

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	C "github.com/ProjectClash/Clash/constant"
	RC "github.com/ProjectClash/Clash/rules/common"
)

var le = binary.LittleEndian

type Compiler struct {
	rules      []byte
	pool       []byte
	targets    []byte
	targetPool []byte
	targetIDs  map[string]uint32

	exact, suffix, keyword []keyRef
	keywordLengths         map[uint32]struct{}
	v4, v6                 []prefixRef

	count, others int
	firstResolve  uint32
	resolvers     []uint32
	source        [32]byte
	err           error
}

type keyRef struct{ off, len, rule uint32 }

type prefixRef struct {
	hi, lo uint64
	bits   uint8
	rule   uint32
}

func NewCompiler() *Compiler {
	return &Compiler{targetIDs: map[string]uint32{}, keywordLengths: map[uint32]struct{}{}, firstResolve: noRule}
}

func (c *Compiler) SetSource(source [32]byte) { c.source = source }

func (c *Compiler) Len() int { return c.count }

func (c *Compiler) AddLine(line string) error { return c.Add(line, nil) }

func (c *Compiler) Add(line string, parsed C.Rule) error {
	if c.err != nil {
		return c.err
	}
	if c.count >= maxRules {
		c.err = fmt.Errorf("more than %d rules", maxRules)
		return c.err
	}
	if wrapper, ok := parsed.(C.RuleWrapper); ok {
		parsed = wrapper.Unwrap()
	}
	index := uint32(c.count)
	kind, flags := byte(kindOther), byte(0)
	text := line
	switch r := parsed.(type) {
	case *RC.Domain:
		kind, text = kindDomain, r.Payload()
	case *RC.DomainSuffix:
		kind, text = kindSuffix, r.Payload()
	case *RC.DomainKeyword:
		kind, text = kindKeyword, r.Payload()
	case *RC.IPCIDR:
		if !r.ClashIsSourceIP() {
			kind, text = kindIP, r.Payload()
			if writtenType(line) == "IP-CIDR6" {
				flags |= flagWrittenIPv6
			}
			if r.ClashResolvesIP() {
				if c.firstResolve == noRule {
					c.firstResolve = index
				}
				c.resolvers = append(c.resolvers, index)
			} else {
				flags |= flagNoResolve
			}
		}
	}
	target := uint32(maxTargets - 1)
	if kind != kindOther {
		var err error
		if target, err = c.target(parsed.Adapter(), index); err != nil {
			c.err = err
			return err
		}
	}
	if len(c.pool)+len(text) > maxRules {
		c.err = errors.New("the rules are more than 2 GiB")
		return c.err
	}
	off := uint32(len(c.pool))
	c.pool = append(c.pool, text...)
	ref := keyRef{off: off, len: uint32(len(text)), rule: index}
	switch kind {
	case kindDomain:
		c.exact = append(c.exact, ref)
	case kindSuffix:
		c.suffix = append(c.suffix, ref)
	case kindKeyword:
		c.keyword = append(c.keyword, ref)
		c.keywordLengths[ref.len] = struct{}{}
	case kindIP:
		prefix := parsed.(*RC.IPCIDR).ClashPrefix().Masked()
		p := prefixRef{bits: uint8(prefix.Bits()), rule: index}
		if prefix.Addr().Is4() {
			a := prefix.Addr().As4()
			p.lo = uint64(binary.BigEndian.Uint32(a[:]))
			c.v4 = append(c.v4, p)
		} else {
			a := prefix.Addr().As16()
			p.hi, p.lo = binary.BigEndian.Uint64(a[:8]), binary.BigEndian.Uint64(a[8:])
			c.v6 = append(c.v6, p)
		}
	default:
		c.others++
	}
	var entry [ruleEntry]byte
	entry[0] = kind | flags<<4
	entry[1], entry[2], entry[3] = byte(target), byte(target>>8), byte(target>>16)
	le.PutUint32(entry[4:], off)
	le.PutUint32(entry[8:], uint32(len(text)))
	c.rules = append(c.rules, entry[:]...)
	c.count++
	return nil
}

func (c *Compiler) target(name string, rule uint32) (uint32, error) {
	if id, ok := c.targetIDs[name]; ok {
		return id, nil
	}
	id := uint32(len(c.targetIDs))
	if id >= maxTargets-1 {
		return 0, fmt.Errorf("more than %d targets", maxTargets-1)
	}
	c.targetIDs[name] = id
	var entry [targetEntr]byte
	le.PutUint32(entry[0:], uint32(len(c.targetPool)))
	le.PutUint32(entry[4:], uint32(len(name)))
	le.PutUint32(entry[8:], rule)
	c.targets = append(c.targets, entry[:]...)
	c.targetPool = append(c.targetPool, name...)
	return id, nil
}

func (c *Compiler) Write(w io.Writer) (int64, [sha256.Size]byte, error) {
	var sum [sha256.Size]byte
	if c.err != nil {
		return 0, sum, c.err
	}
	sections := make([][]byte, sectionCount)
	sections[secTargets] = c.targets
	sections[secTargetPool] = c.targetPool
	sections[secRules] = c.rules
	sections[secPool] = c.pool
	sections[secExact] = buildTable(c.exact, c.pool)
	sections[secSuffix] = buildTable(c.suffix, c.pool)
	sections[secKeyword] = buildTable(c.keyword, c.pool)
	lengths := make([]uint32, 0, len(c.keywordLengths))
	for l := range c.keywordLengths {
		lengths = append(lengths, l)
	}
	sort.Slice(lengths, func(i, j int) bool { return lengths[i] < lengths[j] })
	sections[secKeywordLengths] = u32s(lengths)
	ip := &ipBuilder{listAt: map[string]uint32{}}
	sections[secIPv4Starts], sections[secIPv4Lists] = ip.family(c.v4, false)
	sections[secIPv6Starts], sections[secIPv6Lists] = ip.family(c.v6, true)
	sections[secNodeLists] = u32s(ip.nodeLists)
	sections[secNodes] = u32s(ip.nodes)
	sections[secIPPosts] = u32s(ip.posts)
	sections[secResolvers] = u32s(c.resolvers)

	header := make([]byte, headerSize)
	copy(header, magic)
	le.PutUint32(header[8:], version)
	le.PutUint32(header[12:], uint32(c.count))
	le.PutUint32(header[16:], uint32(c.others))
	le.PutUint32(header[20:], c.firstResolve)
	copy(header[sourceAt:], c.source[:])
	at := headerSize
	for i, section := range sections {
		le.PutUint32(header[sectionsAt+8*i:], uint32(at))
		le.PutUint32(header[sectionsAt+4+8*i:], uint32(len(section)))
		at = align4(at + len(section))
		if at > 1<<32-1-sha256.Size {
			return 0, sum, errors.New("the index is more than 4 GiB")
		}
	}
	hash := sha256.New()
	out := io.MultiWriter(w, hash)
	var written int64
	write := func(b []byte) error {
		n, err := out.Write(b)
		written += int64(n)
		return err
	}
	if err := write(header); err != nil {
		return written, sum, err
	}
	var pad [3]byte
	for _, section := range sections {
		if err := write(section); err != nil {
			return written, sum, err
		}
		if n := align4(len(section)) - len(section); n > 0 {
			if err := write(pad[:n]); err != nil {
				return written, sum, err
			}
		}
	}
	copy(sum[:], hash.Sum(nil))
	n, err := w.Write(sum[:])
	return written + int64(n), sum, err
}

func u32s(values []uint32) []byte {
	out := make([]byte, 4*len(values))
	for i, v := range values {
		le.PutUint32(out[4*i:], v)
	}
	return out
}

func buildTable(refs []keyRef, pool []byte) []byte {
	key := func(r keyRef) []byte { return pool[r.off : r.off+r.len] }
	sort.Slice(refs, func(i, j int) bool {
		if c := bytes.Compare(key(refs[i]), key(refs[j])); c != 0 {
			return c < 0
		}
		return refs[i].rule < refs[j].rule
	})
	type entry struct{ off, len, post uint32 }
	var keys []entry
	var posts []uint32
	for i := 0; i < len(refs); {
		j := i + 1
		for j < len(refs) && bytes.Equal(key(refs[j]), key(refs[i])) {
			j++
		}
		e := entry{off: refs[i].off, len: refs[i].len}
		if j-i == 1 {
			e.post = singlePost | refs[i].rule
		} else {
			e.post = uint32(len(posts))
			posts = append(posts, uint32(j-i))
			for k := i; k < j; k++ {
				posts = append(posts, refs[k].rule)
			}
		}
		keys = append(keys, e)
		i = j
	}
	slots := tableSlots(len(keys))
	out := make([]byte, 12+4*slots+keyEntry*len(keys)+4*len(posts))
	le.PutUint32(out[0:], uint32(slots))
	le.PutUint32(out[4:], uint32(len(keys)))
	le.PutUint32(out[8:], uint32(len(posts)))
	slotAt, keyAt := 12, 12+4*slots
	mask := uint64(slots - 1)
	for i, e := range keys {
		for h := hashOf(pool[e.off:e.off+e.len]) & mask; ; h = (h + 1) & mask {
			if le.Uint32(out[slotAt+4*int(h):]) == 0 {
				le.PutUint32(out[slotAt+4*int(h):], uint32(i+1))
				break
			}
		}
		le.PutUint32(out[keyAt+keyEntry*i:], e.off)
		le.PutUint32(out[keyAt+keyEntry*i+4:], e.len)
		le.PutUint32(out[keyAt+keyEntry*i+8:], e.post)
	}
	postAt := keyAt + keyEntry*len(keys)
	for i, p := range posts {
		le.PutUint32(out[postAt+4*i:], p)
	}
	return out
}

type ipBuilder struct {
	nodeLists []uint32
	nodes     []uint32
	posts     []uint32
	listAt    map[string]uint32
}

func (b *ipBuilder) family(prefixes []prefixRef, v6 bool) (starts, lists []byte) {
	if len(prefixes) == 0 {
		return nil, nil
	}
	sort.Slice(prefixes, func(i, j int) bool {
		a, c := prefixes[i], prefixes[j]
		if a.hi != c.hi {
			return a.hi < c.hi
		}
		if a.lo != c.lo {
			return a.lo < c.lo
		}
		if a.bits != c.bits {
			return a.bits < c.bits
		}
		return a.rule < c.rule
	})
	base := len(b.nodes)
	var distinct []prefixRef
	for i := 0; i < len(prefixes); {
		j := i + 1
		for j < len(prefixes) && prefixes[j].hi == prefixes[i].hi && prefixes[j].lo == prefixes[i].lo && prefixes[j].bits == prefixes[i].bits {
			j++
		}
		rules := make([]uint32, 0, j-i)
		for k := i; k < j; k++ {
			rules = append(rules, prefixes[k].rule)
		}
		distinct = append(distinct, prefixes[i])
		b.nodes = append(b.nodes, b.post(rules))
		i = j
	}
	var codes []uint32
	b.sweep(distinct, base, v6, func(start []byte, ids []uint32) bool {
		starts = append(starts, start...)
		codes = append(codes, b.list(ids))
		return true
	})
	return starts, u32s(codes)
}

func (b *ipBuilder) sweep(prefixes []prefixRef, base int, v6 bool, emit func(start []byte, ids []uint32) bool) {
	if len(prefixes) == 0 {
		return
	}
	width := uint(32)
	if v6 {
		width = 128
	}
	type node struct {
		startHi, startLo, endHi, endLo uint64
		id                             uint32
	}
	end := func(i int) (uint64, uint64) {
		return rangeEnd(prefixes[i].hi, prefixes[i].lo, uint(prefixes[i].bits), width)
	}
	type point struct{ hi, lo uint64 }
	after := make([]point, 0, len(prefixes))
	for i := range prefixes {
		hi, lo := end(i)
		if hi, lo, ok := next(hi, lo, width); ok {
			after = append(after, point{hi, lo})
		}
	}
	less := func(aHi, aLo, bHi, bLo uint64) bool { return aHi < bHi || (aHi == bHi && aLo < bLo) }
	sort.Slice(after, func(i, j int) bool { return less(after[i].hi, after[i].lo, after[j].hi, after[j].lo) })
	var stack []node
	var ids []uint32
	var previous []uint32
	var startBuffer [16]byte
	first := true
	n, a := 0, 0
	at := point{0, 0}
	for {
		for len(stack) > 0 && less(stack[len(stack)-1].endHi, stack[len(stack)-1].endLo, at.hi, at.lo) {
			stack = stack[:len(stack)-1]
		}
		for n < len(prefixes) && prefixes[n].hi == at.hi && prefixes[n].lo == at.lo {
			hi, lo := end(n)
			stack = append(stack, node{prefixes[n].hi, prefixes[n].lo, hi, lo, uint32(base + n)})
			n++
		}
		ids = ids[:0]
		for _, s := range stack {
			ids = append(ids, s.id)
		}
		if first || !equalIDs(ids, previous) {
			first = false
			previous = append(previous[:0], ids...)
			var start []byte
			if v6 {
				binary.BigEndian.PutUint64(startBuffer[:8], at.hi)
				binary.BigEndian.PutUint64(startBuffer[8:], at.lo)
				start = startBuffer[:16]
			} else {
				le.PutUint32(startBuffer[:4], uint32(at.lo))
				start = startBuffer[:4]
			}
			if !emit(start, ids) {
				return
			}
		}
		for a < len(after) && !less(at.hi, at.lo, after[a].hi, after[a].lo) {
			a++
		}
		nextAt, ok := point{}, false
		if n < len(prefixes) {
			nextAt, ok = point{prefixes[n].hi, prefixes[n].lo}, true
		}
		if a < len(after) && (!ok || less(after[a].hi, after[a].lo, nextAt.hi, nextAt.lo)) {
			nextAt, ok = after[a], true
		}
		if !ok {
			return
		}
		at = nextAt
	}
}

func equalIDs(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (b *ipBuilder) list(ids []uint32) uint32 {
	if len(ids) == 0 {
		return noList
	}
	key := string(u32s(ids))
	if at, ok := b.listAt[key]; ok {
		return at
	}
	at := uint32(len(b.nodeLists))
	b.nodeLists = append(b.nodeLists, uint32(len(ids)))
	b.nodeLists = append(b.nodeLists, ids...)
	b.listAt[key] = at
	return at
}

func (b *ipBuilder) post(rules []uint32) uint32 {
	if len(rules) == 1 {
		return singlePost | rules[0]
	}
	at := uint32(len(b.posts))
	b.posts = append(b.posts, uint32(len(rules)))
	b.posts = append(b.posts, rules...)
	return at
}

func rangeEnd(hi, lo uint64, bits, width uint) (uint64, uint64) {
	host := width - bits
	if width == 32 {
		return 0, lo | (uint64(1)<<host - 1)
	}
	switch {
	case host == 0:
		return hi, lo
	case host < 64:
		return hi, lo | (uint64(1)<<host - 1)
	case host == 64:
		return hi, ^uint64(0)
	case host < 128:
		return hi | (uint64(1)<<(host-64) - 1), ^uint64(0)
	default:
		return ^uint64(0), ^uint64(0)
	}
}

func next(hi, lo uint64, width uint) (uint64, uint64, bool) {
	if width == 32 {
		if lo == 0xffffffff {
			return 0, 0, false
		}
		return 0, lo + 1, true
	}
	if lo != ^uint64(0) {
		return hi, lo + 1, true
	}
	if hi == ^uint64(0) {
		return 0, 0, false
	}
	return hi + 1, 0, true
}

func writtenType(line string) string {
	if comma := strings.IndexByte(line, ','); comma >= 0 {
		line = line[:comma]
	}
	return strings.ToUpper(strings.TrimSpace(line))
}
