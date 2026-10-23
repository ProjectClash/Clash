package outbound

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/ProjectClash/Clash/common/clashsum"
	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/log"
)


var nodeLibraryMagic = [4]byte{'C', 'N', 'L', '1'}

const (
	nodeLibraryHeader    = 64
	nodeLibraryEntrySize = 24
)

type NodeLibraryWriter struct {
	provider string
	entries  []nodeLibraryEntry
	names    map[string]struct{}
	groups   []nodeLibraryGroup
}

type nodeLibraryGroup struct {
	name    string
	members []uint32
}

func (w *NodeLibraryWriter) AddGroup(name string, members []uint32) {
	w.groups = append(w.groups, nodeLibraryGroup{name: name, members: members})
}

type nodeLibraryEntry struct {
	name   string
	record []byte
	tp     uint8
	traits catalogTraits
}

func NewNodeLibraryWriter(provider string) *NodeLibraryWriter {
	return &NodeLibraryWriter{provider: provider, names: map[string]struct{}{}}
}

func (w *NodeLibraryWriter) Add(built ProxyAdapter, config string) error {
	name := built.Name()
	if _, seen := w.names[name]; seen {
		return fmt.Errorf("proxy %s is the duplicate name", name)
	}
	record, tp, traits, ok := catalogFacts(built, config, w.provider)
	if !ok {
		return fmt.Errorf("proxy %s cannot be written to a node library", name)
	}
	length, size := binary.Uvarint(record)
	if size <= 0 || int(length) != len(record)-size {
		return fmt.Errorf("proxy %s: a malformed record", name)
	}
	w.names[name] = struct{}{}
	w.entries = append(w.entries, nodeLibraryEntry{name: name, record: record[size:], tp: tp, traits: traits})
	return nil
}

func (w *NodeLibraryWriter) Len() int { return len(w.entries) }

func (w *NodeLibraryWriter) Write(out io.Writer) error {
	count := len(w.entries)
	align := func(n int) int { return (n + 7) &^ 7 }
	providerOffset := nodeLibraryHeader
	tableOffset := align(providerOffset + len(w.provider))
	namesOffset := tableOffset + count*nodeLibraryEntrySize
	namesSize := 0
	for _, e := range w.entries {
		namesSize += len(e.name)
	}
	indexOffset := align(namesOffset + namesSize)
	recordsOffset := align(indexOffset + 4*count)
	recordsSize := 0
	for _, e := range w.entries {
		recordsSize += len(e.record)
	}
	end := recordsOffset + recordsSize
	if end > 1<<32-1 {
		return fmt.Errorf("a node library of %d bytes is past 4 GiB", end)
	}
	buffer := make([]byte, end)
	copy(buffer, nodeLibraryMagic[:])
	le := binary.LittleEndian
	le.PutUint32(buffer[4:], uint32(len(w.provider)))
	le.PutUint64(buffer[8:], uint64(count))
	for i, offset := range []int{providerOffset, tableOffset, namesOffset, indexOffset, recordsOffset, end} {
		le.PutUint64(buffer[16+8*i:], uint64(offset))
	}
	copy(buffer[providerOffset:], w.provider)
	nameAt, recordAt := namesOffset, recordsOffset
	for i, e := range w.entries {
		entry := buffer[tableOffset+i*nodeLibraryEntrySize:]
		le.PutUint32(entry[0:], uint32(nameAt))
		le.PutUint32(entry[4:], uint32(len(e.name)))
		le.PutUint32(entry[8:], uint32(recordAt))
		le.PutUint32(entry[12:], uint32(len(e.record)))
		entry[16] = e.tp
		le.PutUint16(entry[18:], uint16(e.traits))
		copy(buffer[nameAt:], e.name)
		copy(buffer[recordAt:], e.record)
		nameAt += len(e.name)
		recordAt += len(e.record)
	}
	order := make([]uint32, count)
	for i := range order {
		order[i] = uint32(i)
	}
	sort.Slice(order, func(a, b int) bool { return w.entries[order[a]].name < w.entries[order[b]].name })
	for i, node := range order {
		le.PutUint32(buffer[indexOffset+4*i:], node)
	}
	buffer = appendNodeLibraryGroups(buffer, w.groups)
	sum := sha256.Sum256(buffer)
	if _, err := out.Write(buffer); err != nil {
		return err
	}
	_, err := out.Write(sum[:])
	return err
}

func appendNodeLibraryGroups(buffer []byte, groups []nodeLibraryGroup) []byte {
	for len(buffer)%8 != 0 {
		buffer = append(buffer, 0)
	}
	le := binary.LittleEndian
	buffer = le.AppendUint32(buffer, uint32(len(groups)))
	for _, group := range groups {
		buffer = le.AppendUint32(buffer, uint32(len(group.name)))
		buffer = append(buffer, group.name...)
		for len(buffer)%4 != 0 {
			buffer = append(buffer, 0)
		}
		buffer = le.AppendUint32(buffer, uint32(len(group.members)))
		for _, member := range group.members {
			buffer = le.AppendUint32(buffer, member)
		}
	}
	return buffer
}

type NodeLibrary struct {
	data                                 []byte
	count                                int
	provider                             string
	table, names, index, records, endOff int
	groups                               map[string][]uint32
}

func (l *NodeLibrary) Group(name string) ([]uint32, bool) {
	members, ok := l.groups[name]
	return members, ok
}

func OpenNodeLibrary(data []byte) (*NodeLibrary, error) {
	return openNodeLibrary(data, false)
}

func openNodeLibrary(data []byte, hashed bool) (*NodeLibrary, error) {
	if len(data) < nodeLibraryHeader+sha256.Size {
		return nil, fmt.Errorf("a node library of %d bytes is shorter than its header", len(data))
	}
	if [4]byte(data[:4]) != nodeLibraryMagic {
		return nil, errors.New("not a node library")
	}
	le := binary.LittleEndian
	count := le.Uint64(data[8:])
	var offsets [6]uint64
	for i := range offsets {
		offsets[i] = le.Uint64(data[16+8*i:])
	}
	whole := uint64(len(data)) - sha256.Size
	for _, offset := range offsets {
		if offset > whole {
			return nil, fmt.Errorf("a node library's header points at %d, the data is %d bytes", offset, len(data))
		}
	}
	end := offsets[5]
	if !hashed && clashsum.Sum(data[:whole]) != [sha256.Size]byte(data[whole:]) {
		return nil, errors.New("a node library's checksum does not match its bytes")
	}
	if count > end/nodeLibraryEntrySize {
		return nil, fmt.Errorf("a node library's count %d is out of range", count)
	}
	l := &NodeLibrary{data: data, count: int(count)}
	l.table, l.names, l.index, l.records, l.endOff = int(offsets[1]), int(offsets[2]), int(offsets[3]), int(offsets[4]), int(end)
	if offsets[0] != nodeLibraryHeader || !(offsets[0] <= offsets[1] && offsets[1] <= offsets[2] && offsets[2] <= offsets[3] && offsets[3] <= offsets[4] && offsets[4] <= end) ||
		l.names-l.table != l.count*nodeLibraryEntrySize || l.index+4*l.count > l.records {
		return nil, errors.New("a node library's sections are out of order")
	}
	providerLen := uint64(le.Uint32(data[4:]))
	if providerLen > offsets[1]-offsets[0] {
		return nil, errors.New("a node library's provider name runs past its section")
	}
	l.provider = string(data[offsets[0] : offsets[0]+providerLen])
	for i := 0; i < l.count; i++ {
		nameAt, nameLen, recordAt, recordLen := l.entry(i)
		if nameAt < l.names || nameAt+nameLen > l.index || recordAt < l.records || recordAt+recordLen > l.endOff {
			return nil, fmt.Errorf("a node library's node %d points outside its sections", i)
		}
		if node := int(le.Uint32(data[l.index+4*i:])); node >= l.count {
			return nil, fmt.Errorf("a node library's index names node %d of %d", node, l.count)
		}
	}
	groups, err := readNodeLibraryGroups(data[:whole], int(end))
	if err != nil {
		return nil, err
	}
	l.groups = groups
	return l, nil
}

func readNodeLibraryGroups(data []byte, end int) (map[string][]uint32, error) {
	at := (end + 7) &^ 7
	if at >= len(data) {
		return nil, nil
	}
	le := binary.LittleEndian
	if at+4 > len(data) {
		return nil, errors.New("a node library's groups run past its end")
	}
	n := int(le.Uint32(data[at:]))
	at += 4
	if n > (len(data)-at)/8 {
		return nil, errors.New("a node library holds more groups than its bytes")
	}
	groups := make(map[string][]uint32, n)
	for i := 0; i < n; i++ {
		if at+4 > len(data) {
			return nil, errors.New("a node library's group runs past its end")
		}
		nameLen := int(le.Uint32(data[at:]))
		at += 4
		if nameLen > len(data)-at {
			return nil, errors.New("a node library's group name runs past its end")
		}
		name := unsafe.String(unsafe.SliceData(data[at:]), nameLen)
		at = (at + nameLen + 3) &^ 3
		if at+4 > len(data) {
			return nil, errors.New("a node library's group runs past its end")
		}
		count := int(le.Uint32(data[at:]))
		at += 4
		if count > (len(data)-at)/4 {
			return nil, errors.New("a node library's group holds more members than its bytes")
		}
		var members []uint32
		if count > 0 {
			members = unsafe.Slice((*uint32)(unsafe.Pointer(&data[at])), count)
		}
		groups[name] = members
		at += 4 * count
	}
	if at != len(data) {
		return nil, errors.New("a node library's groups do not end where it does")
	}
	return groups, nil
}

func (l *NodeLibrary) entry(i int) (nameAt, nameLen, recordAt, recordLen int) {
	e := l.data[l.table+i*nodeLibraryEntrySize:]
	le := binary.LittleEndian
	return int(le.Uint32(e[0:])), int(le.Uint32(e[4:])), int(le.Uint32(e[8:])), int(le.Uint32(e[12:]))
}

func (l *NodeLibrary) Len() int { return l.count }

func (l *NodeLibrary) ProviderName() string { return l.provider }

func (l *NodeLibrary) nameBytes(i int) []byte {
	at, n, _, _ := l.entry(i)
	return l.data[at : at+n]
}

func (l *NodeLibrary) Name(i int) string {
	b := l.nameBytes(i)
	if len(b) == 0 {
		return ""
	}
	return unsafe.String(&b[0], len(b))
}

func (l *NodeLibrary) Type(i int) C.AdapterType {
	return C.AdapterType(l.data[l.table+i*nodeLibraryEntrySize+16])
}

func (l *NodeLibrary) traits(i int) catalogTraits {
	return catalogTraits(binary.LittleEndian.Uint16(l.data[l.table+i*nodeLibraryEntrySize+18:]))
}

func (l *NodeLibrary) record(i int) []byte {
	_, _, at, n := l.entry(i)
	return l.data[at : at+n]
}

func (l *NodeLibrary) SortedAt(k int) int {
	return int(binary.LittleEndian.Uint32(l.data[l.index+4*k:]))
}

func (l *NodeLibrary) Rank(name string) int {
	key := unsafe.Slice(unsafe.StringData(name), len(name))
	return sort.Search(l.count, func(j int) bool {
		return bytes.Compare(l.nameBytes(l.SortedAt(j)), key) >= 0
	})
}

func (l *NodeLibrary) Lookup(name string) (int, bool) {
	key := unsafe.Slice(unsafe.StringData(name), len(name))
	le := binary.LittleEndian
	position := sort.Search(l.count, func(j int) bool {
		node := int(le.Uint32(l.data[l.index+4*j:]))
		return bytes.Compare(l.nameBytes(node), key) >= 0
	})
	if position == l.count {
		return 0, false
	}
	node := int(le.Uint32(l.data[l.index+4*position:]))
	if !bytes.Equal(l.nameBytes(node), key) {
		return 0, false
	}
	return node, true
}

func NewLibraryNodeStore(library *NodeLibrary, dialerForAPI C.Dialer, tunnelForAPI C.Tunnel, build NodeBuilder) *NodeStore {
	s := NewNodeStore(library.ProviderName(), dialerForAPI, tunnelForAPI, build)
	s.library = library
	return s
}

func LibraryCatalogNode(store *NodeStore, i int) ProxyAdapter {
	l := store.library
	return &catalogNode{name: l.Name(i), store: store, ref: uint32(i), tp: uint8(l.Type(i)), traits: l.traits(i)}
}

func OpenNodeLibraryFile(path string, want [sha256.Size]byte) (*NodeLibrary, error) {
	if info, err := os.Stat(path); err == nil {
		if value, ok := mappedNodeLibraries.Load(libraryMappingKeyOf(want, info)); ok {
			library := value.(*NodeLibrary)
			if !info.Mode().IsRegular() || info.Size() != int64(len(library.data)) || !provenOrHashes(path, info, want) {
				return nil, fmt.Errorf("node library %s is not the one the configuration names", path)
			}
			return library, nil
		}
	}
	at := time.Now()
	file, err := openLibraryFile(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() < nodeLibraryHeader+sha256.Size || info.Size() > 1<<32 {
		return nil, fmt.Errorf("node library %s: %d bytes", path, info.Size())
	}
	data, err := mapNodeRecords(file, int(info.Size()))
	if err != nil {
		return nil, fmt.Errorf("node library %s: %w", path, err)
	}
	if [sha256.Size]byte(data[len(data)-sha256.Size:]) != want {
		unmapNodeRecords(data)
		return nil, fmt.Errorf("node library %s is not the one the configuration names", path)
	}
	stamp, stamped := clashsum.StampOf(info)
	library, err := openNodeLibrary(data, stamped && clashsum.ProvenAt(path, stamp, want))
	if err != nil {
		unmapNodeRecords(data)
		return nil, fmt.Errorf("node library %s: %w", path, err)
	}
	if stamped {
		clashsum.Prove(stamp, at, want)
	}
	if mapped, loaded := mappedNodeLibraries.LoadOrStore(libraryMappingKeyOf(want, info), library); loaded {
		unmapNodeRecords(data)
		return mapped.(*NodeLibrary), nil
	}
	count, total := mappedLibraryCount.Add(1), mappedLibraryBytes.Add(int64(len(data)))
	log.Infoln("[Library] mapped %s (%d nodes, %d bytes); this run maps %d libraries, %d bytes", path, library.Len(), len(data), count, total)
	return library, nil
}

var mappedLibraryCount, mappedLibraryBytes atomic.Int64

var mappedNodeLibraries sync.Map

type libraryMappingKey struct {
	sum      [sha256.Size]byte
	dev, ino uint64
}

func libraryMappingKeyOf(sum [sha256.Size]byte, info os.FileInfo) libraryMappingKey {
	key := libraryMappingKey{sum: sum}
	key.dev, key.ino = fileIdentity(info)
	return key
}

func openLibraryFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}

func provenOrHashes(path string, info os.FileInfo, want [sha256.Size]byte) bool {
	if stamp, ok := clashsum.StampOf(info); ok && clashsum.ProvenAt(path, stamp, want) {
		return true
	}
	return clashsum.Hashes(path, want)
}


func libraryNodeAt(store *NodeStore, i int) *catalogNode {
	l := store.library
	return &catalogNode{name: l.Name(i), store: store, ref: uint32(i), tp: uint8(l.Type(i)), traits: l.traits(i)}
}

func LibraryNodeAnswers(store *NodeStore, i int) (udp, uot, l3 bool) {
	traits := store.library.traits(i)
	return traits&catalogUDP != 0, traits&catalogUOT != 0, traits&catalogL3 != 0
}

func LibraryNodeAddr(store *NodeStore, i int) string {
	defer runtime.KeepAlive(store)
	record, heap := store.record(uint32(i))
	return text(viewNodeRecord(record).addr, heap)
}

func LibraryNodeProxyInfo(store *NodeStore, i int) C.ProxyInfo {
	defer runtime.KeepAlive(store)
	record, heap := store.record(uint32(i))
	return proxyInfoOfRecord(store, store.library.traits(i), viewNodeRecord(record), heap)
}

func LibraryNodeView(store *NodeStore, i int) ProxyAdapter { return libraryNodeAt(store, i) }

func (s *NodeStore) Library() *NodeLibrary { return s.library }

func CatalogNodeHoldsNothing(a C.ProxyAdapter) bool {
	node, ok := catalogNodeOf(a)
	if !ok || node.use.inUse() {
		return false
	}
	nodeCatalog.mu.Lock()
	defer nodeCatalog.mu.Unlock()
	_, pinned := nodeCatalog.pinned[node]
	return node.expanded.Load() == nil && node.probe == nil && !pinned
}

func CheckNodeLibraryFile(path string, want [sha256.Size]byte) error {
	at := time.Now()
	file, err := openLibraryFile(path)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() < nodeLibraryHeader+sha256.Size || info.Size() > 1<<32 {
		return fmt.Errorf("node library %s: %d bytes", path, info.Size())
	}
	data, err := mapNodeRecords(file, int(info.Size()))
	if err != nil {
		return err
	}
	defer unmapNodeRecords(data)
	if [sha256.Size]byte(data[len(data)-sha256.Size:]) != want {
		return fmt.Errorf("node library %s is not the one named", path)
	}
	stamp, stamped := clashsum.StampOf(info)
	if _, err = openNodeLibrary(data, stamped && clashsum.ProvenAt(path, stamp, want)); err == nil && stamped {
		clashsum.Prove(stamp, at, want)
	}
	return err
}
