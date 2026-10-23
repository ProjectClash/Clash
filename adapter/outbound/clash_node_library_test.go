package outbound

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"
	"runtime"
	"testing"
	"time"
	"unsafe"

	"github.com/ProjectClash/Clash/common/clashsum"
	C "github.com/ProjectClash/Clash/constant"
)

func libraryAligned(data []byte) []byte {
	if len(data) == 0 {
		return []byte{}
	}
	words := make([]uint64, (len(data)+7)/8)
	out := unsafe.Slice((*byte)(unsafe.Pointer(&words[0])), len(data))
	copy(out, data)
	return out
}

func libraryTestNodes(t *testing.T, n int) ([]ProxyAdapter, []string) {
	t.Helper()
	var nodes []ProxyAdapter
	var configs []string
	for i := 0; i < n; i++ {
		var node ProxyAdapter
		var err error
		name := fmt.Sprintf("节点 %d <&>", n-i)
		if i%2 == 0 {
			node, err = NewSocks5(Socks5Option{BasicOption: BasicOption{DialerProxy: "via"}, Name: name, Server: "127.0.0.1", Port: 1000 + i, UDP: true})
		} else {
			node = NewDirectWithOption(DirectOption{BasicOption: BasicOption{}, Name: name})
		}
		if err != nil {
			t.Fatal(err)
		}
		nodes = append(nodes, node)
		configs = append(configs, fmt.Sprintf("config-%d", i))
	}
	return nodes, configs
}

func TestANodeLibraryAnswersWhatItsNodesWere(t *testing.T) {
	nodes, configs := libraryTestNodes(t, 300)
	writer := NewNodeLibraryWriter("airport")
	for i, node := range nodes {
		if err := writer.Add(node, configs[i]); err != nil {
			t.Fatal(err)
		}
	}
	var buffer bytes.Buffer
	if err := writer.Write(&buffer); err != nil {
		t.Fatal(err)
	}
	library, err := OpenNodeLibrary(libraryAligned(buffer.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if library.Len() != len(nodes) || library.ProviderName() != "airport" {
		t.Fatalf("library of %d nodes for %q", library.Len(), library.ProviderName())
	}
	for i, node := range nodes {
		index, ok := library.Lookup(node.Name())
		if !ok || index != i {
			t.Fatalf("%q: index %d, %v", node.Name(), index, ok)
		}
		if library.Name(i) != node.Name() || library.Type(i) != node.Type() {
			t.Fatalf("%d: %q %v", i, library.Name(i), library.Type(i))
		}
		traits := library.traits(i)
		if (traits&catalogUDP != 0) != node.SupportUDP() || (traits&catalogUOT != 0) != node.SupportUOT() {
			t.Fatalf("%d: traits %b", i, traits)
		}
		view := viewNodeRecord(library.record(i))
		if string(view.config) != configs[i] || string(view.addr) != node.Addr() || string(view.dialerProxy) != node.ProxyInfo().DialerProxy {
			t.Fatalf("%d: record %q %q %q", i, view.config, view.addr, view.dialerProxy)
		}
	}
	if _, ok := library.Lookup("节点 0"); ok {
		t.Fatal("found a name the library does not hold")
	}
}

func TestANodeLibraryRefusesARepeatedName(t *testing.T) {
	writer := NewNodeLibraryWriter("")
	if err := writer.Add(NewDirectWithOption(DirectOption{Name: "same"}), "a"); err != nil {
		t.Fatal(err)
	}
	if err := writer.Add(NewDirectWithOption(DirectOption{Name: "same"}), "b"); err == nil {
		t.Fatal("a repeated name was taken")
	}
}

func TestANodeLibraryRefusesBytesThatAreNotOne(t *testing.T) {
	nodes, configs := libraryTestNodes(t, 5)
	writer := NewNodeLibraryWriter("p")
	for i, node := range nodes {
		_ = writer.Add(node, configs[i])
	}
	var buffer bytes.Buffer
	if err := writer.Write(&buffer); err != nil {
		t.Fatal(err)
	}
	whole := buffer.Bytes()
	for _, cut := range []int{0, 8, 63, len(whole) / 2, len(whole) - 1} {
		if _, err := OpenNodeLibrary(libraryAligned(whole[:cut])); err == nil {
			t.Fatalf("a library cut to %d of %d bytes opened", cut, len(whole))
		}
	}
	for _, at := range []int{0, 9, 70, len(whole) / 2, len(whole) - 1} {
		changed := append([]byte(nil), whole...)
		changed[at] ^= 0x40
		if _, err := OpenNodeLibrary(libraryAligned(changed)); err == nil {
			t.Fatalf("a library with byte %d changed opened", at)
		}
	}
}

func TestALibraryNodeIsTheNodeItWasWrittenFrom(t *testing.T) {
	nodes, configs := libraryTestNodes(t, 40)
	writer := NewNodeLibraryWriter("airport")
	for i, node := range nodes {
		if err := writer.Add(node, configs[i]); err != nil {
			t.Fatal(err)
		}
	}
	var buffer bytes.Buffer
	if err := writer.Write(&buffer); err != nil {
		t.Fatal(err)
	}
	library, err := OpenNodeLibrary(libraryAligned(buffer.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	var built []string
	store := NewLibraryNodeStore(library, nil, nil, func(config string, _ C.Dialer, _ C.Tunnel, provider string) (ProxyAdapter, error) {
		built = append(built, provider+"/"+config)
		return NewDirectWithOption(DirectOption{Name: "built"}), nil
	})
	for i, original := range nodes {
		node := LibraryCatalogNode(store, i)
		wantJSON, _ := original.MarshalJSON()
		gotJSON, err := node.MarshalJSON()
		if err != nil || string(gotJSON) != string(wantJSON) {
			t.Fatalf("%d: JSON\n got  %s\n want %s", i, gotJSON, wantJSON)
		}
		if node.Name() != original.Name() || node.Type() != original.Type() || node.Addr() != original.Addr() ||
			node.SupportUDP() != original.SupportUDP() || node.ProxyInfo() != original.ProxyInfo() {
			t.Fatalf("%d: %q %v %q %v %+v", i, node.Name(), node.Type(), node.Addr(), node.SupportUDP(), node.ProxyInfo())
		}
	}
	node := LibraryCatalogNode(store, 7)
	if conn, err := node.DialContext(context.Background(), &C.Metadata{Host: "localhost", DstPort: 1}); err == nil {
		_ = conn.Close()
	}
	if len(built) == 0 || built[len(built)-1] != "airport/"+configs[7] {
		t.Fatalf("the first dial built %v", built)
	}
}

func TestANodeLibraryWithOffsetsPastItsDataIsRefused(t *testing.T) {
	data := make([]byte, 96)
	copy(data, nodeLibraryMagic[:])
	le := binary.LittleEndian
	le.PutUint32(data[4:], 1000)
	le.PutUint64(data[8:], 0)
	max := ^uint64(0)
	for i, offset := range []uint64{nodeLibraryHeader, max - 7, max - 7, max - 7, max - 7, max} {
		le.PutUint64(data[16+8*i:], offset)
	}
	sum := sha256.Sum256(data[:len(data)-sha256.Size])
	copy(data[len(data)-sha256.Size:], sum[:])
	if _, err := OpenNodeLibrary(data); err == nil {
		t.Fatal("a library pointing past its data was opened")
	}
}

func TestALibraryOpenedAgainIsTheMappingItHas(t *testing.T) {
	writer := NewNodeLibraryWriter("")
	var buffer bytes.Buffer
	if err := writer.Write(&buffer); err != nil {
		t.Fatal(err)
	}
	data := buffer.Bytes()
	dir := t.TempDir()
	a, b := dir+"/a.library", dir+"/b.library"
	for _, path := range []string{a, b} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	sum := [sha256.Size]byte(data[len(data)-sha256.Size:])
	first, err := OpenNodeLibraryFile(a, sum)
	if err != nil {
		t.Fatal(err)
	}
	if again, err := OpenNodeLibraryFile(a, sum); err != nil || again != first {
		t.Fatalf("opened again: %v, the same mapping %v", err, again == first)
	}
	second, err := OpenNodeLibraryFile(b, sum)
	if err != nil || second == first {
		t.Fatalf("another file of the same content: %v, the first file's mapping %v", err, second == first)
	}
	if again, err := OpenNodeLibraryFile(b, sum); err != nil || again != second {
		t.Fatalf("the second file opened again: %v", err)
	}
	changed := bytes.Clone(data)
	changed[nodeLibraryHeader/2] ^= 0xff
	if err := os.WriteFile(b, changed, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenNodeLibraryFile(b, sum); err == nil {
		t.Fatal("a changed file of the same size reused the mapping")
	}
	if err := os.Remove(b); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenNodeLibraryFile(b, sum); err == nil {
		t.Fatal("a file gone reused the mapping")
	}
	if again, err := OpenNodeLibraryFile(a, sum); err != nil || again != first {
		t.Fatalf("the file mapped, opened again: %v", err)
	}
	if err := os.WriteFile(a, changed, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenNodeLibraryFile(a, sum); err == nil {
		t.Fatal("the file mapped, rewritten in place, reused the mapping")
	}
	c := dir + "/c.library"
	if err := os.WriteFile(c, data, 0o600); err != nil {
		t.Fatal(err)
	}
	third, err := OpenNodeLibraryFile(c, sum)
	if err != nil || third == first || !bytes.Equal(third.data, data) {
		t.Fatalf("an intact copy beside a changed mapping: %v, the changed mapping %v", err, third == first)
	}
}

func TestALibraryOpenedAgainUnchangedIsNotHashedAgain(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("no change time on this platform")
	}
	writer := NewNodeLibraryWriter("")
	var buffer bytes.Buffer
	if err := writer.Write(&buffer); err != nil {
		t.Fatal(err)
	}
	data := buffer.Bytes()
	path := t.TempDir() + "/a.library"
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := [sha256.Size]byte(data[len(data)-sha256.Size:])
	time.Sleep(300 * time.Millisecond)
	steps := []struct {
		name  string
		step  func() error
		wants int64
	}{
		{"checked", func() error { return CheckNodeLibraryFile(path, sum) }, 1},
		{"opened", func() error { _, err := OpenNodeLibraryFile(path, sum); return err }, 0},
		{"opened again", func() error { _, err := OpenNodeLibraryFile(path, sum); return err }, 0},
		{"checked again", func() error { return CheckNodeLibraryFile(path, sum) }, 0},
	}
	for _, s := range steps {
		before := clashsum.Hashed()
		if err := s.step(); err != nil {
			t.Fatalf("%s: %v", s.name, err)
		}
		if hashes := clashsum.Hashed() - before; hashes != s.wants {
			t.Errorf("%s: hashed %d times, want %d", s.name, hashes, s.wants)
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	changed := bytes.Clone(data)
	changed[nodeLibraryHeader/2] ^= 0xff
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteAt(changed, 0); err != nil {
		t.Fatal(err)
	}
	file.Close()
	if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenNodeLibraryFile(path, sum); err == nil {
		t.Fatal("a library rewritten in place after its proof reused the mapping")
	}
}
