package outbound

import (
	"context"
	"fmt"
	"io"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/transport/sudoku"
)

func clashSudokuTableCached(key clashSudokuTableKey) bool {
	clashSudokuTableCache.Lock()
	defer clashSudokuTableCache.Unlock()
	return clashSudokuTableCache.slots[key] != nil
}

func clashSudokuOption(key string) SudokuOption {
	return SudokuOption{Name: "sudoku", Server: "127.0.0.1", Port: 9, Key: key}
}

func TestParsedSudokuNodesHoldNoTable(t *testing.T) {
	clashRequireParsedNodesHoldNothing(t, "sudoku", func(i int) (io.Closer, error) {
		return NewSudoku(clashSudokuOption(fmt.Sprint("key-", i)))
	})
}

func clashSudokuMetadata() *C.Metadata {
	return &C.Metadata{NetWork: C.TCP, Host: "example.com", DstPort: 80}
}

func clashDialRefused(t *testing.T, node *Sudoku) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if conn, err := node.DialContext(ctx, clashSudokuMetadata()); err == nil {
		_ = conn.Close()
		t.Fatal("a dial to a closed port connected")
	}
}

func TestSudokuNodesOfOneKeyHoldOneTableSet(t *testing.T) {
	port := clashClosedPort(t, "tcp")
	held := func(keys []string) int64 {
		heapBefore, _ := clashSettle()
		nodes := make([]*Sudoku, 0, len(keys))
		for _, key := range keys {
			option := clashSudokuOption(key)
			option.Port = port
			node, err := NewSudoku(option)
			if err != nil {
				t.Fatal(err)
			}
			nodes = append(nodes, node)
		}
		for _, node := range nodes {
			clashDialRefused(t, node)
		}
		heapAfter, _ := clashSettle()
		runtime.KeepAlive(nodes)
		for _, node := range nodes {
			_ = node.Close()
		}
		return heapAfter - heapBefore
	}
	one := t.Name() + "-one"
	shared := held([]string{one, one, one, one})
	distinct := held([]string{t.Name() + "-a", t.Name() + "-b", t.Name() + "-c", t.Name() + "-d"})
	t.Logf("four dialed nodes hold %d bytes with one key, %d bytes with four", shared, distinct)
	if shared*2 > distinct {
		t.Fatalf("four nodes of one key hold %d bytes, four of four keys %d: equal tables must be shared", shared, distinct)
	}
}

func TestSudokuFirstDialsBuildOneTableSetPerKey(t *testing.T) {
	port := clashClosedPort(t, "tcp")
	buildsBefore := clashSudokuTableBuilds.Load()
	keys := []string{t.Name() + "-x", t.Name() + "-x", t.Name() + "-x", t.Name() + "-y", t.Name() + "-y"}
	nodes := make([]*Sudoku, len(keys))
	for i, key := range keys {
		option := clashSudokuOption(key)
		option.Port = port
		node, err := NewSudoku(option)
		if err != nil {
			t.Fatal(err)
		}
		nodes[i] = node
	}
	if built := clashSudokuTableBuilds.Load() - buildsBefore; built != 0 {
		t.Fatalf("parsing built %d table sets", built)
	}
	var dials sync.WaitGroup
	for _, node := range nodes {
		for i := 0; i < 8; i++ {
			dials.Add(1)
			go func(node *Sudoku) {
				defer dials.Done()
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if conn, err := node.DialContext(ctx, clashSudokuMetadata()); err == nil {
					_ = conn.Close()
				}
			}(node)
		}
	}
	dials.Wait()
	if built := clashSudokuTableBuilds.Load() - buildsBefore; built != 2 {
		t.Fatalf("40 racing first dials over two keys built %d table sets, want 2", built)
	}
	x, y := nodes[0].clashTables.set.Load(), nodes[3].clashTables.set.Load()
	if x == nil || y == nil || x == y {
		t.Fatalf("the two keys hold sets %p and %p", x, y)
	}
	for i, node := range nodes {
		want := x
		if i >= 3 {
			want = y
		}
		if got := node.clashTables.set.Load(); got != want {
			t.Fatalf("node %d holds set %p, its key's set is %p", i, got, want)
		}
	}
	xKey, yKey := nodes[0].clashTables.spec.key, nodes[3].clashTables.spec.key
	if !clashSudokuTableCached(xKey) || !clashSudokuTableCached(yKey) {
		t.Fatal("the cache does not hold the keys the nodes dialed")
	}

	for _, node := range nodes {
		_ = node.Close()
	}
	nodes, x, y = nil, nil, nil
	for i := 0; i < 100 && (clashSudokuTableCached(xKey) || clashSudokuTableCached(yKey)); i++ {
		runtime.GC()
		time.Sleep(5 * time.Millisecond)
	}
	if clashSudokuTableCached(xKey) || clashSudokuTableCached(yKey) {
		t.Fatal("the cache still holds a key after every node holding its set was collected")
	}

	option := clashSudokuOption(keys[0])
	option.Port = port
	node, err := NewSudoku(option)
	if err != nil {
		t.Fatal(err)
	}
	clashDialRefused(t, node)
	if built := clashSudokuTableBuilds.Load() - buildsBefore; built != 3 {
		t.Fatalf("a key let go and dialed again: %d sets built in all, want 3", built)
	}
	_ = node.Close()
}

func TestSudokuSettingsAreStillRefusedAtParse(t *testing.T) {
	tableErr := func(tableType, customTable string, customTables []string) string {
		_, err := sudoku.NewClientTablesWithCustomPatterns("seed", tableType, customTable, customTables)
		if err == nil {
			t.Fatalf("the reference builder accepted %q %q %q", tableType, customTable, customTables)
		}
		return "build table(s) failed: " + err.Error()
	}
	padding := 200
	cases := []struct {
		name   string
		modify func(*SudokuOption)
		want   string
	}{
		{"custom table", func(o *SudokuOption) { o.CustomTable = "xxxxvvvv" }, tableErr("prefer_entropy", "xxxxvvvv", nil)},
		{"short custom table", func(o *SudokuOption) { o.CustomTable = "xpxvvpv" }, tableErr("prefer_entropy", "xpxvvpv", nil)},
		{"custom tables", func(o *SudokuOption) { o.CustomTables = []string{"bad"} }, tableErr("prefer_entropy", "", []string{"bad"})},
		{"directional custom table", func(o *SudokuOption) {
			o.TableType = "up_ascii_down_entropy"
			o.CustomTable = "xxxxvvvv"
		}, tableErr("up_ascii_down_entropy", "xxxxvvvv", nil)},
		{"table type", func(o *SudokuOption) { o.TableType = "bogus" }, "table-type must be"},
		{"aead method", func(o *SudokuOption) { o.AEADMethod = "bogus" }, "invalid aead-method: bogus"},
		{"padding", func(o *SudokuOption) { o.PaddingMin = &padding }, "padding-min must be between 0 and 100"},
		{"path root", func(o *SudokuOption) { o.PathRoot = "a/b" }, "invalid http-mask-path-root"},
		{"multiplex", func(o *SudokuOption) { o.Multiplex = "sometimes" }, "invalid multiplex"},
	}
	buildsBefore := clashSudokuTableBuilds.Load()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			option := clashSudokuOption(t.Name())
			tc.modify(&option)
			node, err := NewSudoku(option)
			if err == nil {
				_ = node.Close()
				t.Fatalf("parse accepted a node upstream refuses (%s)", tc.want)
			}
			if !strings.HasPrefix(err.Error(), tc.want) {
				t.Fatalf("parse refused with %q, upstream with %q", err.Error(), tc.want)
			}
		})
	}
	if built := clashSudokuTableBuilds.Load() - buildsBefore; built != 0 {
		t.Fatalf("refusing %d nodes built %d table sets", len(cases), built)
	}
}

func TestSudokuTableRotationIsSharedInOrder(t *testing.T) {
	port := clashClosedPort(t, "tcp")
	patterns := []string{"xpxvvpvv", "vvpxxpvv"}
	reference, err := sudoku.NewClientTablesWithCustomPatterns(sudoku.ClientAEADSeed(t.Name()), "prefer_entropy", "", patterns)
	if err != nil {
		t.Fatal(err)
	}
	var nodes []*Sudoku
	for i := 0; i < 2; i++ {
		option := clashSudokuOption(t.Name())
		option.Port = port
		option.CustomTables = patterns
		node, err := NewSudoku(option)
		if err != nil {
			t.Fatal(err)
		}
		clashDialRefused(t, node)
		nodes = append(nodes, node)
	}
	set := nodes[0].clashTables.set.Load()
	if set == nil || set != nodes[1].clashTables.set.Load() {
		t.Fatal("two nodes of one key and rotation hold different sets")
	}
	if len(set.tables) != len(reference) {
		t.Fatalf("%d tables, upstream builds %d", len(set.tables), len(reference))
	}
	for i := range reference {
		if set.tables[i].Hint() != reference[i].Hint() || fmt.Sprint(set.tables[i].EncodeTable[7]) != fmt.Sprint(reference[i].EncodeTable[7]) {
			t.Fatalf("table %d differs from the one upstream builds", i)
		}
	}
	for _, node := range nodes {
		_ = node.Close()
	}
}
