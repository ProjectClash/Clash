package clashindex

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"unsafe"
)

type Index struct {
	data          []byte
	count, others int
	firstResolve  uint32
	source        [32]byte
	section       [sectionCount][]byte

	targets     []string
	targetFirst []uint32

	exact, suffix, keyword table
	keywordLengths         []int

	verify bool
}

type table struct {
	slots, keys, posts []byte
	slotCount          int
	mask               uint64
	pool               []byte
}

func Open(path string, want [sha256.Size]byte) (*Index, error) {
	return open(path, want, false)
}

func OpenVerified(path string, want [sha256.Size]byte) (*Index, error) {
	return open(path, want, true)
}

var lastOpened struct {
	sync.Mutex
	path     string
	want     [sha256.Size]byte
	size     int64
	modified int64
	identity any
	verified bool
	index    *Index
}

func open(path string, want [sha256.Size]byte, verify bool) (*Index, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	lastOpened.Lock()
	defer lastOpened.Unlock()
	if l := &lastOpened; l.index != nil && l.path == path && l.want == want && l.size == info.Size() &&
		l.modified == info.ModTime().UnixNano() && os.SameFile(l.identity.(os.FileInfo), info) && (l.verified || !verify) {
		if fileHashes(path, want) {
			return l.index, nil
		}
		return nil, errors.New("not the index the configuration names")
	}
	index, opened, err := openFile(path, want, verify)
	if err != nil {
		return nil, err
	}
	lastOpened.path, lastOpened.want, lastOpened.size, lastOpened.modified = path, want, opened.Size(), opened.ModTime().UnixNano()
	lastOpened.identity, lastOpened.verified, lastOpened.index = opened, verify, index
	return index, nil
}

func fileHashes(path string, want [sha256.Size]byte) bool {
	file, err := openIndexFile(path)
	if err != nil {
		return false
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < sha256.Size {
		return false
	}
	hash := sha256.New()
	if _, err := io.CopyN(hash, file, info.Size()-sha256.Size); err != nil {
		return false
	}
	var trailer [sha256.Size]byte
	if _, err := io.ReadFull(file, trailer[:]); err != nil {
		return false
	}
	return trailer == want && [sha256.Size]byte(hash.Sum(nil)) == want
}

func openFile(path string, want [sha256.Size]byte, verify bool) (*Index, os.FileInfo, error) {
	file, err := openIndexFile(path)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, nil, errors.New("not a regular file")
	}
	if info.Size() < headerSize+sha256.Size || info.Size() > 1<<32-1 {
		return nil, nil, fmt.Errorf("an index of %d bytes", info.Size())
	}
	data, err := mapIndex(file, int(info.Size()))
	if err != nil {
		return nil, nil, err
	}
	index, err := decode(data, &want, verify)
	if err != nil {
		unmapIndex(data)
		return nil, nil, err
	}
	runtime.AddCleanup(index, unmapIndex, data)
	return index, info, nil
}

func Decode(data []byte) (*Index, error) {
	return decode(data, nil, true)
}

func decode(data []byte, want *[sha256.Size]byte, verify bool) (*Index, error) {
	if len(data) < headerSize+sha256.Size || string(data[:8]) != magic {
		return nil, errors.New("not a rule index")
	}
	body := data[:len(data)-sha256.Size]
	trailer := [sha256.Size]byte(data[len(data)-sha256.Size:])
	if want != nil && trailer != *want {
		return nil, errors.New("not the index the configuration names")
	}
	if sha256.Sum256(body) != trailer {
		return nil, errors.New("index checksum")
	}
	if v := le.Uint32(data[8:]); v != version {
		return nil, fmt.Errorf("index version %d", v)
	}
	x := &Index{data: data, verify: verify}
	x.count = int(le.Uint32(data[12:]))
	x.others = int(le.Uint32(data[16:]))
	x.firstResolve = le.Uint32(data[20:])
	copy(x.source[:], data[sourceAt:sectionsAt])
	for i := range x.section {
		off, n := int(le.Uint32(data[sectionsAt+8*i:])), int(le.Uint32(data[sectionsAt+4+8*i:]))
		if off < headerSize || off%4 != 0 || n < 0 || off+n > len(body) {
			return nil, fmt.Errorf("section %d out of range", i)
		}
		x.section[i] = body[off : off+n : off+n]
	}
	if err := x.check(); err != nil {
		return nil, err
	}
	return x, nil
}

func (x *Index) Source() [32]byte { return x.source }

func (x *Index) check() error {
	if x.count < 0 || x.count > maxRules || len(x.section[secRules]) != ruleEntry*x.count {
		return errors.New("rule count")
	}
	pool := x.section[secPool]
	targets, targetPool := x.section[secTargets], x.section[secTargetPool]
	if len(targets)%targetEntr != 0 {
		return errors.New("targets")
	}
	for at := 0; at < len(targets); at += targetEntr {
		off, n, first := le.Uint32(targets[at:]), le.Uint32(targets[at+4:]), le.Uint32(targets[at+8:])
		if uint64(off)+uint64(n) > uint64(len(targetPool)) || int(first) >= x.count {
			return errors.New("target out of range")
		}
		x.targets = append(x.targets, string(targetPool[off:off+n]))
		x.targetFirst = append(x.targetFirst, first)
	}
	others := 0
	var resolvers []uint32
	rules := x.section[secRules]
	for i := 0; i < x.count; i++ {
		e := rules[ruleEntry*i:]
		kind, flags, target := e[0]&0x0f, e[0]>>4, uint32(e[1])|uint32(e[2])<<8|uint32(e[3])<<16
		off, n := le.Uint32(e[4:]), le.Uint32(e[8:])
		if uint64(off)+uint64(n) > uint64(len(pool)) {
			return fmt.Errorf("rule %d out of range", i)
		}
		switch kind {
		case kindOther:
			others++
			continue
		case kindDomain, kindSuffix, kindKeyword:
			if n == 0 {
				return fmt.Errorf("rule %d has no payload", i)
			}
		case kindIP:
			if flags&flagNoResolve == 0 {
				resolvers = append(resolvers, uint32(i))
			}
		default:
			return fmt.Errorf("rule %d of kind %d", i, kind)
		}
		if int(target) >= len(x.targets) {
			return fmt.Errorf("rule %d names no target", i)
		}
	}
	if others != x.others {
		return errors.New("other rule count")
	}
	if !bytes.Equal(x.section[secResolvers], u32s(resolvers)) {
		return errors.New("resolving rules")
	}
	if (len(resolvers) == 0 && x.firstResolve != noRule) || (len(resolvers) > 0 && x.firstResolve != resolvers[0]) {
		return errors.New("first resolving rule")
	}
	var err error
	if x.exact, err = x.readTable(x.section[secExact], kindDomain); err != nil {
		return err
	}
	if x.suffix, err = x.readTable(x.section[secSuffix], kindSuffix); err != nil {
		return err
	}
	if x.keyword, err = x.readTable(x.section[secKeyword], kindKeyword); err != nil {
		return err
	}
	if x.verify {
		if err := x.checkEveryRuleKeyed(); err != nil {
			return err
		}
	}
	lengths := x.section[secKeywordLengths]
	if len(lengths)%4 != 0 {
		return errors.New("keyword lengths")
	}
	for at := 0; at < len(lengths); at += 4 {
		l := int(le.Uint32(lengths[at:]))
		if l == 0 || (len(x.keywordLengths) > 0 && l <= x.keywordLengths[len(x.keywordLengths)-1]) {
			return errors.New("keyword lengths")
		}
		x.keywordLengths = append(x.keywordLengths, l)
	}
	if x.verify {
		if err := x.verifyDerived(); err != nil {
			return err
		}
	}
	return x.checkIP()
}

func (x *Index) readTable(b []byte, kind byte) (table, error) {
	if len(b) == 0 {
		return table{}, nil
	}
	if len(b) < 12 {
		return table{}, errors.New("table")
	}
	slots, keys, posts := int(le.Uint32(b)), int(le.Uint32(b[4:])), int(le.Uint32(b[8:]))
	if slots == 0 && keys == 0 && posts == 0 && len(b) == 12 {
		return table{}, nil
	}
	if slots < 8 || slots&(slots-1) != 0 || keys >= slots || keys == 0 || 12+4*slots+keyEntry*keys+4*posts != len(b) {
		return table{}, errors.New("table sections do not add up")
	}
	t := table{pool: x.section[secPool], slotCount: slots, mask: uint64(slots - 1)}
	at := 12
	t.slots = b[at : at+4*slots]
	at += 4 * slots
	t.keys = b[at : at+keyEntry*keys]
	at += keyEntry * keys
	t.posts = b[at:]
	occupied := 0
	for i := 0; i < slots; i++ {
		s := le.Uint32(t.slots[4*i:])
		if int(s) > keys {
			return table{}, errors.New("slot out of range")
		}
		if s != 0 {
			occupied++
		}
	}
	if x.verify && occupied != keys {
		return table{}, errors.New("slots and keys differ")
	}
	for i := 0; i < keys; i++ {
		k := t.keys[keyEntry*i:]
		off, n := le.Uint32(k), le.Uint32(k[4:])
		if n == 0 || uint64(off)+uint64(n) > uint64(len(t.pool)) {
			return table{}, errors.New("key out of range")
		}
		key := t.pool[off : off+n]
		if x.verify {
			if found, _, ok := t.findBytes(key); !ok || found != i {
				return table{}, errors.New("a key is not where its table finds it")
			}
		}
		if err := x.checkPost(le.Uint32(k[8:]), t.posts, func(rule uint32) bool {
			kindOf, payload := x.kindAndPayload(rule)
			return kindOf == kind && (!x.verify || bytes.Equal(payload, key))
		}); err != nil {
			return table{}, err
		}
	}
	return t, nil
}

func (x *Index) verifyDerived() error {
	lengths := map[int]bool{}
	for i := 0; i < len(x.keyword.keys)/keyEntry; i++ {
		lengths[int(le.Uint32(x.keyword.keys[keyEntry*i+4:]))] = true
	}
	if len(lengths) != len(x.keywordLengths) {
		return errors.New("keyword lengths are not the keywords'")
	}
	for _, l := range x.keywordLengths {
		if !lengths[l] {
			return errors.New("keyword lengths are not the keywords'")
		}
	}
	first := make([]int, len(x.targets))
	for i := range first {
		first[i] = -1
	}
	for i := 0; i < x.count; i++ {
		kind, _, target, payload, _ := x.entry(i)
		if kind == kindOther {
			continue
		}
		if kind != kindIP && !lowered(payload) {
			return fmt.Errorf("rule %d's domain is not in lower case", i)
		}
		if first[target] < 0 {
			first[target] = i
		}
	}
	for id, at := range first {
		if at < 0 || at != int(x.targetFirst[id]) {
			return errors.New("targets are not the rules'")
		}
	}
	return nil
}

func lowered(payload []byte) bool {
	for _, c := range payload {
		if c >= 0x80 {
			s := string(payload)
			return s == strings.ToLower(s)
		}
		if 'A' <= c && c <= 'Z' {
			return false
		}
	}
	return true
}

func (x *Index) checkEveryRuleKeyed() error {
	var want [kindIP + 1]int
	rules := x.section[secRules]
	for i := 0; i < x.count; i++ {
		want[rules[ruleEntry*i]&0x0f]++
	}
	for kind, t := range map[byte]table{kindDomain: x.exact, kindSuffix: x.suffix, kindKeyword: x.keyword} {
		got := 0
		for i := 0; i < len(t.keys)/keyEntry; i++ {
			got += postLen(le.Uint32(t.keys[keyEntry*i+8:]), t.posts)
		}
		if got != want[kind] {
			return fmt.Errorf("the tables hold %d rules of kind %d, not %d", got, kind, want[kind])
		}
	}
	return nil
}

func postLen(post uint32, posts []byte) int {
	if post&singlePost != 0 {
		return 1
	}
	return int(le.Uint32(posts[4*int(post):]))
}

func (x *Index) kindAndPayload(rule uint32) (byte, []byte) {
	kind, _, _, payload, ok := x.entry(int(rule))
	if !ok {
		return 0xff, nil
	}
	return kind, payload
}


func word(b []byte, at int) (uint32, bool) {
	if at < 0 || at+4 > len(b) {
		return 0, false
	}
	return le.Uint32(b[at:]), true
}

func span(b []byte, off, n uint32) ([]byte, bool) {
	if uint64(off)+uint64(n) > uint64(len(b)) {
		return nil, false
	}
	return b[off : off+n], true
}

func (x *Index) checkPost(post uint32, posts []byte, ok func(rule uint32) bool) error {
	if post&singlePost != 0 {
		if !ok(post &^ singlePost) {
			return errors.New("a post names a rule not of its key")
		}
		return nil
	}
	at := 4 * int(post)
	if at+4 > len(posts) {
		return errors.New("post out of range")
	}
	n := int(le.Uint32(posts[at:]))
	if n < 2 || at+4+4*n > len(posts) {
		return errors.New("post out of range")
	}
	previous := -1
	for i := 0; i < n; i++ {
		rule := le.Uint32(posts[at+4+4*i:])
		if int(rule) <= previous || !ok(rule) {
			return errors.New("a post names a rule not of its key")
		}
		previous = int(rule)
	}
	return nil
}

func (x *Index) checkIP() error {
	nodes, nodeLists, posts := x.section[secNodes], x.section[secNodeLists], x.section[secIPPosts]
	if len(nodes)%4 != 0 || len(nodeLists)%4 != 0 || len(posts)%4 != 0 {
		return errors.New("IP sections")
	}
	count := len(nodes) / 4
	rules := x.section[secRules]
	for i := 0; i < x.count; i++ {
		if rules[ruleEntry*i]&0x0f != kindIP {
			continue
		}
		if _, payload := x.kindAndPayload(uint32(i)); !validPrefix(payload) {
			return fmt.Errorf("rule %d is not a prefix", i)
		}
	}
	for id := 0; id < count; id++ {
		if err := x.checkPost(le.Uint32(nodes[4*id:]), posts, func(rule uint32) bool {
			kind, _ := x.kindAndPayload(rule)
			return kind == kindIP
		}); err != nil {
			return err
		}
	}
	checkLists := func(starts, lists []byte, width int) error {
		if len(starts)%width != 0 || len(lists) != 4*(len(starts)/width) {
			return errors.New("IP ranges")
		}
		if len(starts) > 0 && !bytes.Equal(starts[:width], make([]byte, width)) {
			return errors.New("IP ranges start past 0")
		}
		for i := 0; i < len(lists)/4; i++ {
			list := le.Uint32(lists[4*i:])
			if list == noList {
				continue
			}
			at := 4 * int(list)
			if at+4 > len(nodeLists) {
				return errors.New("node list out of range")
			}
			n := int(le.Uint32(nodeLists[at:]))
			if n < 1 || at+4+4*n > len(nodeLists) {
				return errors.New("node list out of range")
			}
			for k := 0; k < n; k++ {
				if int(le.Uint32(nodeLists[at+4+4*k:])) >= count {
					return errors.New("node out of range")
				}
			}
		}
		return nil
	}
	if err := checkLists(x.section[secIPv4Starts], x.section[secIPv4Lists], 4); err != nil {
		return err
	}
	if err := checkLists(x.section[secIPv6Starts], x.section[secIPv6Lists], 16); err != nil {
		return err
	}
	if !x.verify {
		return nil
	}
	return x.verifyIP(count)
}

func validPrefix(payload []byte) bool {
	_, err := netip.ParsePrefix(unsafeString(payload))
	return err == nil
}

func (x *Index) verifyIP(count int) error {
	nodes, nodeLists, posts := x.section[secNodes], x.section[secNodeLists], x.section[secIPPosts]
	prefixes := make([]prefixRef, count)
	v6 := make([]bool, count)
	seen := make([]uint64, (x.count+63)/64)
	held, ipRules := 0, 0
	for i := 0; i < x.count; i++ {
		if x.section[secRules][ruleEntry*i]&0x0f == kindIP {
			ipRules++
		}
	}
	for id := 0; id < count; id++ {
		var first netip.Prefix
		have := false
		err := x.checkPost(le.Uint32(nodes[4*id:]), posts, func(rule uint32) bool {
			_, payload := x.kindAndPayload(rule)
			if seen[rule/64]&(1<<(rule%64)) != 0 {
				return false
			}
			p, err := netip.ParsePrefix(unsafeString(payload))
			if err != nil {
				return false
			}
			p = p.Masked()
			if have && p != first {
				return false
			}
			first, have = p, true
			seen[rule/64] |= 1 << (rule % 64)
			held++
			return true
		})
		if err != nil {
			return err
		}
		ref := prefixRef{bits: uint8(first.Bits())}
		if first.Addr().Is4() {
			a := first.Addr().As4()
			ref.lo = uint64(binary.BigEndian.Uint32(a[:]))
		} else {
			a := first.Addr().As16()
			ref.hi, ref.lo = binary.BigEndian.Uint64(a[:8]), binary.BigEndian.Uint64(a[8:])
			v6[id] = true
		}
		prefixes[id] = ref
	}
	if held != ipRules {
		return errors.New("an IP rule is in no node")
	}
	split := 0
	for split < count && !v6[split] {
		split++
	}
	for id := split; id < count; id++ {
		if !v6[id] {
			return errors.New("IP nodes out of order")
		}
	}
	builder := &ipBuilder{}
	check := func(family []prefixRef, base int, isV6 bool, starts, lists []byte) error {
		for i := 1; i < len(family); i++ {
			a, b := family[i-1], family[i]
			if !(a.hi < b.hi || (a.hi == b.hi && (a.lo < b.lo || (a.lo == b.lo && a.bits < b.bits)))) {
				return errors.New("IP nodes out of order")
			}
		}
		width := 4
		if isV6 {
			width = 16
		}
		k := 0
		wrong := false
		builder.sweep(family, base, isV6, func(start []byte, ids []uint32) bool {
			if 4*k+4 > len(lists) || !bytes.Equal(starts[width*k:width*k+width], start) {
				wrong = true
				return false
			}
			list := le.Uint32(lists[4*k:])
			k++
			if (list == noList) != (len(ids) == 0) {
				wrong = true
				return false
			}
			if list == noList {
				return true
			}
			at := 4 * int(list)
			if int(le.Uint32(nodeLists[at:])) != len(ids) {
				wrong = true
				return false
			}
			for i, id := range ids {
				if le.Uint32(nodeLists[at+4+4*i:]) != id {
					wrong = true
					return false
				}
			}
			return true
		})
		if wrong || 4*k != len(lists) {
			return errors.New("IP ranges are not their prefixes'")
		}
		return nil
	}
	if err := check(prefixes[:split], 0, false, x.section[secIPv4Starts], x.section[secIPv4Lists]); err != nil {
		return err
	}
	return check(prefixes[split:], split, true, x.section[secIPv6Starts], x.section[secIPv6Lists])
}

func (x *Index) Len() int { return x.count }

func (x *Index) OtherCount() int { return x.others }

func (x *Index) Targets(f func(name string, firstRule int) bool) {
	for i, name := range x.targets {
		if !f(name, int(x.targetFirst[i])) {
			return
		}
	}
}

func (x *Index) Others(f func(index int, line string) bool) {
	for i := 0; i < x.count; i++ {
		kind, _, _, payload, ok := x.entry(i)
		if !ok || kind != kindOther {
			continue
		}
		if !f(i, string(payload)) {
			return
		}
	}
}

func (x *Index) MappedTypeAndTarget(i int) (tp, target string, ok bool) {
	kind, flags, id, _, ok := x.entry(i)
	if !ok {
		return "", "", false
	}
	if tp = mappedType(kind, flags); tp == "" {
		return "", "", false
	}
	target, ok = x.target(id)
	return tp, target, ok
}

func (x *Index) Written(i int) (line string, mapped, ok bool) {
	kind, flags, id, payload, ok := x.entry(i)
	if !ok {
		return "", false, false
	}
	if kind == kindOther {
		return string(payload), false, true
	}
	tp := mappedType(kind, flags)
	target, ok := x.target(id)
	if tp == "" || !ok {
		return "", false, false
	}
	line = tp + "," + string(payload) + "," + target
	if kind == kindIP && flags&flagNoResolve != 0 {
		line += ",no-resolve"
	}
	return line, true, true
}

func mappedType(kind, flags byte) string {
	switch kind {
	case kindDomain:
		return "DOMAIN"
	case kindSuffix:
		return "DOMAIN-SUFFIX"
	case kindKeyword:
		return "DOMAIN-KEYWORD"
	case kindIP:
		if flags&flagWrittenIPv6 != 0 {
			return "IP-CIDR6"
		}
		return "IP-CIDR"
	}
	return ""
}

func (x *Index) entry(i int) (kind, flags byte, target uint32, payload []byte, ok bool) {
	rules := x.section[secRules]
	if i < 0 || ruleEntry*i+ruleEntry > len(rules) {
		return 0, 0, 0, nil, false
	}
	e := rules[ruleEntry*i : ruleEntry*i+ruleEntry]
	payload, ok = span(x.section[secPool], le.Uint32(e[4:]), le.Uint32(e[8:]))
	return e[0] & 0x0f, e[0] >> 4, uint32(e[1]) | uint32(e[2])<<8 | uint32(e[3])<<16, payload, ok
}

func (x *Index) target(id uint32) (string, bool) {
	if int(id) >= len(x.targets) {
		return "", false
	}
	return x.targets[id], true
}

func (x *Index) resolverCount() int { return len(x.section[secResolvers]) / 4 }
func (x *Index) resolver(k int) uint32 {
	at, ok := word(x.section[secResolvers], 4*k)
	if !ok {
		return noRule
	}
	return at
}
func (x *Index) resolverFrom(from uint32) int {
	return sort.Search(x.resolverCount(), func(k int) bool { return x.resolver(k) >= from })
}

func unsafeBytes(s string) []byte {
	return unsafe.Slice(unsafe.StringData(s), len(s))
}

func unsafeString(b []byte) string {
	return unsafe.String(unsafe.SliceData(b), len(b))
}

func (t *table) findBytes(key []byte) (int, uint32, bool) {
	if t.slotCount == 0 {
		return 0, 0, false
	}
	h := hashOf(key) & t.mask
	for probes := 0; probes < t.slotCount; probes, h = probes+1, (h+1)&t.mask {
		s, ok := word(t.slots, 4*int(h))
		if !ok || s == 0 {
			return 0, 0, false
		}
		at := keyEntry * (int(s) - 1)
		if at+keyEntry > len(t.keys) {
			return 0, 0, false
		}
		e := t.keys[at : at+keyEntry]
		if stored, ok := span(t.pool, le.Uint32(e), le.Uint32(e[4:])); ok && bytes.Equal(stored, key) {
			return int(s - 1), le.Uint32(e[8:]), true
		}
	}
	return 0, 0, false
}

func (t *table) find(key string) (int, uint32, bool) { return t.findBytes(unsafeBytes(key)) }

type cursor struct {
	single    uint32
	hasSingle bool
	list      []byte
}

func cursorOf(post uint32, posts []byte) cursor {
	if post&singlePost != 0 {
		return cursor{single: post &^ singlePost, hasSingle: true}
	}
	at := 4 * int(post)
	n, ok := word(posts, at)
	if !ok || uint64(at)+4+4*uint64(n) > uint64(len(posts)) {
		return cursor{}
	}
	return cursor{list: posts[at+4 : at+4+4*int(n)]}
}

func (c *cursor) head() uint32 {
	if c.hasSingle {
		return c.single
	}
	if len(c.list) >= 4 {
		return le.Uint32(c.list)
	}
	return noRule
}

func (c *cursor) advance() {
	if c.hasSingle {
		c.hasSingle = false
	} else if len(c.list) >= 4 {
		c.list = c.list[4:]
	}
}

func (c *cursor) seek(from uint32) {
	if c.hasSingle {
		if c.single < from {
			c.hasSingle = false
		}
		return
	}
	n := len(c.list) / 4
	k := sort.Search(n, func(i int) bool { return le.Uint32(c.list[4*i:]) >= from })
	c.list = c.list[4*k:]
}

func smallest(cursors []cursor) (int, uint32) {
	which, head := -1, uint32(noRule)
	for i := range cursors {
		if h := cursors[i].head(); h < head {
			which, head = i, h
		}
	}
	return which, head
}

func (x *Index) hostCursors(host string, out []cursor) []cursor {
	if host == "" {
		return out
	}
	if _, post, ok := x.exact.find(host); ok {
		out = append(out, cursorOf(post, x.exact.posts))
	}
	if x.suffix.slotCount > 0 {
		if _, post, ok := x.suffix.find(host); ok {
			out = append(out, cursorOf(post, x.suffix.posts))
		}
		for i := 0; i < len(host); i++ {
			if host[i] == '.' {
				if _, post, ok := x.suffix.find(host[i+1:]); ok {
					out = append(out, cursorOf(post, x.suffix.posts))
				}
			}
		}
	}
	var seenBuffer [32]int
	seen := seenBuffer[:0]
	for _, l := range x.keywordLengths {
		if l > len(host) {
			break
		}
		for i := 0; i+l <= len(host); i++ {
			key, post, ok := x.keyword.find(host[i : i+l])
			if !ok || containsInt(seen, key) {
				continue
			}
			seen = append(seen, key)
			out = append(out, cursorOf(post, x.keyword.posts))
		}
	}
	return out
}

func containsInt(s []int, v int) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func (x *Index) ipCursors(ip netip.Addr, from uint32, out []cursor) []cursor {
	if !ip.IsValid() {
		return out
	}
	ip = ip.WithZone("")
	var list uint32
	if ip.Is4() {
		starts := x.section[secIPv4Starts]
		n := len(starts) / 4
		if n == 0 {
			return out
		}
		a := ip.As4()
		v := binary.BigEndian.Uint32(a[:])
		k := sort.Search(n, func(i int) bool { return le.Uint32(starts[4*i:]) > v }) - 1
		var ok bool
		if list, ok = word(x.section[secIPv4Lists], 4*k); !ok {
			return out
		}
	} else {
		starts := x.section[secIPv6Starts]
		n := len(starts) / 16
		if n == 0 {
			return out
		}
		a := ip.As16()
		k := sort.Search(n, func(i int) bool { return bytes.Compare(starts[16*i:16*i+16], a[:]) > 0 }) - 1
		var ok bool
		if list, ok = word(x.section[secIPv6Lists], 4*k); !ok {
			return out
		}
	}
	if list == noList {
		return out
	}
	lists, nodes, posts := x.section[secNodeLists], x.section[secNodes], x.section[secIPPosts]
	at := 4 * int(list)
	n, _ := word(lists, at)
	for i := 0; i < int(n) && i < 130; i++ {
		node, ok := word(lists, at+4+4*i)
		if !ok {
			break
		}
		post, ok := word(nodes, 4*int(node))
		if !ok {
			continue
		}
		c := cursorOf(post, posts)
		c.seek(from)
		if c.head() != noRule {
			out = append(out, c)
		}
	}
	return out
}
