package outbound

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	C "github.com/ProjectClash/Clash/constant"

	"github.com/gofrs/uuid/v5"
)

func storeRecords(t *testing.T, s *NodeStore, n int, size func(i int) int) []uint32 {
	t.Helper()
	refs := make([]uint32, n)
	for i := range refs {
		config := strings.Repeat(string(rune('a'+i%26)), size(i))
		info := C.ProxyInfo{Interface: "en0", RoutingMark: -i, DialerProxy: "hop", ProviderName: "p"}
		ref, err := s.add(encodeNodeRecord(uuid.UUID{byte(i)}, i%2 == 0, `{"x":1}`, "host:443", info, "p", config))
		if err != nil {
			t.Fatal(err)
		}
		refs[i] = ref
	}
	return refs
}

func checkRecords(t *testing.T, s *NodeStore, refs []uint32, size func(i int) int, wantHeap bool) {
	t.Helper()
	for i, ref := range refs {
		record, heap := s.record(ref)
		if heap != wantHeap {
			t.Fatalf("record %d: heap %v, want %v", i, heap, wantHeap)
		}
		v := viewNodeRecord(record)
		if v.baseJSON != (i%2 == 0) || string(v.config) != strings.Repeat(string(rune('a'+i%26)), size(i)) ||
			string(v.addr) != "host:443" || string(v.iface) != "en0" || v.routingMark != -i || string(v.dialerProxy) != "hop" || v.ownProvider {
			t.Fatalf("record %d reads back wrong: %+v", i, v)
		}
		if v.baseJSON && v.id != (uuid.UUID{byte(i)}) || !v.baseJSON && string(v.json) != `{"x":1}` {
			t.Fatalf("record %d: id/json wrong", i)
		}
	}
}

func TestNodeStoreRecordsReadBack(t *testing.T) {
	size := func(i int) int {
		if i == 7 {
			return 3 * nodeStoreChunk
		}
		return 100 + i%300
	}
	s := NewNodeStore("p", nil, nil, nil)
	refs := storeRecords(t, s, 1000, size)
	checkRecords(t, s, refs, size, true)
	dir := t.TempDir()
	if err := s.Seal(dir); err != nil {
		t.Fatal(err)
	}
	if _, mapped := s.Bytes(); !mapped {
		t.Fatal("not mapped")
	}
	checkRecords(t, s, refs, size, false)
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("files left behind: %v", entries)
	}
	if _, err := s.add([]byte{1, 0}); err == nil {
		t.Fatal("a sealed store took a record")
	}
}

func TestASealThatFailsLeavesTheRecordsOnTheHeap(t *testing.T) {
	size := func(int) int { return 50 }
	s := NewNodeStore("p", nil, nil, nil)
	refs := storeRecords(t, s, 10, size)
	blocked := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocked, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Seal(filepath.Join(blocked, "dir")); err == nil {
		t.Fatal("sealed into a path under a file")
	}
	if _, mapped := s.Bytes(); mapped {
		t.Fatal("mapped after a failed seal")
	}
	checkRecords(t, s, refs, size, true)
}

func TestASingleNodeStoreHoldsItsRecordOnly(t *testing.T) {
	s := newSingleNodeStore("p", nil, nil, nil)
	storeRecords(t, s, 1, func(int) int { return 40 })
	if n, _ := s.Bytes(); n > 128 {
		t.Fatalf("a single record's store holds %d B", n)
	}
	if len(s.chunks) != 1 || len(s.chunks[0]) > 128 {
		t.Fatalf("chunks %d of %d B", len(s.chunks), len(s.chunks[0]))
	}
}

func TestASweepKeepsWhatThisProcessMadeAndWhatALiveProcessHolds(t *testing.T) {
	dir := t.TempDir()
	nodeStoreFiles.Lock()
	nodeStoreFiles.seq++
	made := nodeStoreFiles.seq
	nodeStoreFiles.Unlock()
	mine := fmt.Sprintf("nodes-%d-%d.tmp", os.Getpid(), made)
	notMine := fmt.Sprintf("nodes-%d-%d.catalog", os.Getpid(), made+1000)
	alive := fmt.Sprintf("nodes-%d-1.catalog", os.Getppid())
	for _, name := range []string{mine, notMine, alive} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if removed := SweepNodeStoreFiles(dir); removed != 1 {
		t.Fatalf("removed %d; want 1", removed)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var left []string
	for _, entry := range entries {
		left = append(left, entry.Name())
	}
	want := []string{mine, alive}
	slices.Sort(want)
	if !slices.Equal(left, want) {
		t.Fatalf("left %v; want %v", left, want)
	}
}
