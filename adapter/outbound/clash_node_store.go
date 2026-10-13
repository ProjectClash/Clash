package outbound

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"unsafe"

	C "github.com/ProjectClash/Clash/constant"

	"github.com/gofrs/uuid/v5"
)


type NodeBuilder func(config string, dialerForAPI C.Dialer, tunnelForAPI C.Tunnel, providerName string) (ProxyAdapter, error)

const (
	nodeStoreChunk      = 32 << 10
	nodeStoreOffsetBits = 15
)

type NodeStore struct {
	providerName string
	dialerForAPI C.Dialer
	tunnelForAPI C.Tunnel
	build        NodeBuilder
	single       bool

	mu     sync.RWMutex
	chunks [][]byte
	used   int
	mapped *mappedNodeRecords
	library *NodeLibrary
}

type mappedNodeRecords struct {
	data   []byte
	starts []uint32
}

func NewNodeStore(providerName string, dialerForAPI C.Dialer, tunnelForAPI C.Tunnel, build NodeBuilder) *NodeStore {
	return &NodeStore{providerName: providerName, dialerForAPI: dialerForAPI, tunnelForAPI: tunnelForAPI, build: build}
}

func newSingleNodeStore(providerName string, dialerForAPI C.Dialer, tunnelForAPI C.Tunnel, build NodeBuilder) *NodeStore {
	s := NewNodeStore(providerName, dialerForAPI, tunnelForAPI, build)
	s.single = true
	return s
}

func (s *NodeStore) Holds(providerName string, dialerForAPI C.Dialer, tunnelForAPI C.Tunnel) bool {
	return s.providerName == providerName && sameInterface(s.dialerForAPI, dialerForAPI) && sameInterface(s.tunnelForAPI, tunnelForAPI)
}

func sameInterface(a, b any) (same bool) {
	defer func() {
		if recover() != nil {
			same = false
		}
	}()
	return a == b
}

func (s *NodeStore) add(record []byte) (uint32, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.mapped != nil {
		return 0, errors.New("node store: sealed")
	}
	last := len(s.chunks) - 1
	if last < 0 || s.used+len(record) > len(s.chunks[last]) {
		if len(s.chunks) >= 1<<(32-nodeStoreOffsetBits) {
			return 0, errors.New("node store: full")
		}
		size := nodeStoreChunk
		if s.single || len(record) > size {
			size = len(record)
		}
		s.chunks = append(s.chunks, make([]byte, size))
		last, s.used = len(s.chunks)-1, 0
	}
	ref := uint32(last)<<nodeStoreOffsetBits | uint32(s.used)
	copy(s.chunks[last][s.used:], record)
	s.used += len(record)
	return ref, nil
}

func (s *NodeStore) record(ref uint32) (data []byte, heap bool) {
	if s.library != nil {
		return s.library.record(int(ref)), true
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	chunk, offset := ref>>nodeStoreOffsetBits, ref&(1<<nodeStoreOffsetBits-1)
	if m := s.mapped; m != nil {
		start := int(m.starts[chunk]) + int(offset)
		return recordAt(m.data[start:]), false
	}
	return recordAt(s.chunks[chunk][offset:]), true
}

func recordAt(b []byte) []byte {
	n, size := binary.Uvarint(b)
	return b[size : size+int(n)]
}

func (s *NodeStore) Bytes() (n int, mapped bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.mapped != nil {
		return len(s.mapped.data), true
	}
	for i, chunk := range s.chunks {
		if i == len(s.chunks)-1 {
			n += s.used
		} else {
			n += len(chunk)
		}
	}
	return n, false
}

var nodeStoreFiles struct {
	sync.Mutex
	seq uint64
}

func (s *NodeStore) Seal(dir string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if dir == "" || s.mapped != nil || len(s.chunks) == 0 {
		return nil
	}
	m, err := s.mapLocked(dir)
	if err != nil {
		return fmt.Errorf("node store: %w", err)
	}
	s.mapped, s.chunks = m, nil
	runtime.AddCleanup(s, unmapNodeRecords, m.data)
	return nil
}

func (s *NodeStore) mapLocked(dir string) (*mappedNodeRecords, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	nodeStoreFiles.Lock()
	nodeStoreFiles.seq++
	name := fmt.Sprintf("nodes-%d-%d", os.Getpid(), nodeStoreFiles.seq)
	nodeStoreFiles.Unlock()
	temporary := filepath.Join(dir, name+".tmp")
	final := filepath.Join(dir, name+".catalog")
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	defer os.Remove(temporary)
	starts := make([]uint32, len(s.chunks))
	size := 0
	for i, chunk := range s.chunks {
		if i == len(s.chunks)-1 {
			chunk = chunk[:s.used]
		}
		starts[i] = uint32(size)
		if _, err = file.Write(chunk); err != nil {
			break
		}
		size += len(chunk)
	}
	var written os.FileInfo
	if err == nil {
		err = file.Sync()
	}
	if err == nil {
		written, err = file.Stat()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return nil, err
	}
	if size == 0 || size > 1<<31 {
		return nil, fmt.Errorf("%d bytes of records", size)
	}
	if err := os.Rename(temporary, final); err != nil {
		return nil, err
	}
	defer os.Remove(final)
	before, err := os.Lstat(final)
	if err != nil {
		return nil, err
	}
	mapped, err := os.Open(final)
	if err != nil {
		return nil, err
	}
	defer mapped.Close()
	after, err := mapped.Stat()
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || !os.SameFile(written, before) || !os.SameFile(before, after) || after.Size() != int64(size) {
		return nil, errors.New("the file opened is not the file written")
	}
	data, err := mapNodeRecords(mapped, size)
	if err != nil {
		return nil, err
	}
	return &mappedNodeRecords{data: data, starts: starts}, nil
}

func SweepNodeStoreFiles(dir string) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	nodeStoreFiles.Lock()
	taken := nodeStoreFiles.seq
	nodeStoreFiles.Unlock()
	own := os.Getpid()
	removed := 0
	for _, entry := range entries {
		name := entry.Name()
		stem, ok := strings.CutSuffix(name, ".tmp")
		if !ok {
			if stem, ok = strings.CutSuffix(name, ".catalog"); !ok {
				continue
			}
		}
		pidText, seqText, ok := strings.Cut(strings.TrimPrefix(stem, "nodes-"), "-")
		if !ok || !strings.HasPrefix(stem, "nodes-") || !digits(pidText) || !digits(seqText) || !entry.Type().IsRegular() {
			continue
		}
		pid, pidErr := strconv.ParseInt(pidText, 10, 32)
		seq, seqErr := strconv.ParseUint(seqText, 10, 64)
		if pidErr != nil || seqErr != nil || pid <= 0 {
			continue
		}
		if int(pid) == own {
			if seq <= taken {
				continue
			}
		} else if !nodeStoreProcessGone(int(pid)) {
			continue
		}
		if os.Remove(filepath.Join(dir, name)) == nil {
			removed++
		}
	}
	return removed
}

func digits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

const (
	recordBaseJSON byte = 1 << iota
	recordProvider
)

func appendRecordString(b []byte, s string) []byte {
	b = binary.AppendUvarint(b, uint64(len(s)))
	return append(b, s...)
}

func encodeNodeRecord(id uuid.UUID, baseJSON bool, json string, addr string, info C.ProxyInfo, storeProvider string, config string) []byte {
	body := make([]byte, 0, 32+len(json)+len(addr)+len(info.Interface)+len(info.DialerProxy)+len(config))
	var flags byte
	if baseJSON {
		flags |= recordBaseJSON
	}
	if info.ProviderName != storeProvider {
		flags |= recordProvider
	}
	body = append(body, flags)
	if baseJSON {
		body = append(body, id[:]...)
	} else {
		body = appendRecordString(body, json)
	}
	if flags&recordProvider != 0 {
		body = appendRecordString(body, info.ProviderName)
	}
	body = appendRecordString(body, addr)
	body = appendRecordString(body, info.Interface)
	body = binary.AppendVarint(body, int64(info.RoutingMark))
	body = appendRecordString(body, info.DialerProxy)
	body = appendRecordString(body, config)
	out := binary.AppendUvarint(make([]byte, 0, len(body)+binary.MaxVarintLen32), uint64(len(body)))
	return append(out, body...)
}

type nodeRecordView struct {
	baseJSON    bool
	id          uuid.UUID
	ownProvider bool
	provider    []byte
	json        []byte
	addr        []byte
	iface       []byte
	routingMark int
	dialerProxy []byte
	config      []byte
}

func readRecordString(b []byte) (field, rest []byte) {
	n, size := binary.Uvarint(b)
	return b[size : size+int(n)], b[size+int(n):]
}

func viewNodeRecord(b []byte) (v nodeRecordView) {
	flags := b[0]
	b = b[1:]
	if flags&recordBaseJSON != 0 {
		v.baseJSON = true
		copy(v.id[:], b[:16])
		b = b[16:]
	} else {
		v.json, b = readRecordString(b)
	}
	if flags&recordProvider != 0 {
		v.ownProvider = true
		v.provider, b = readRecordString(b)
	}
	v.addr, b = readRecordString(b)
	v.iface, b = readRecordString(b)
	mark, size := binary.Varint(b)
	v.routingMark, b = int(mark), b[size:]
	v.dialerProxy, b = readRecordString(b)
	v.config, _ = readRecordString(b)
	return v
}

func text(field []byte, heap bool) string {
	if len(field) == 0 {
		return ""
	}
	if heap {
		return unsafe.String(&field[0], len(field))
	}
	return strings.Clone(unsafe.String(&field[0], len(field)))
}
