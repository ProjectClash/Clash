package outbound

import (
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"weak"

	"github.com/ProjectClash/Clash/transport/sudoku"
	obfs "github.com/ProjectClash/Clash/transport/sudoku/obfs/sudoku"
)


type clashSudokuTableKey struct {
	seed      string
	tableType string
	patterns  string
}

type clashSudokuTableSpec struct {
	key          clashSudokuTableKey
	customTable  string
	customTables []string
}

type clashSudokuTableSet struct {
	tables []*obfs.Table
}

type clashSudokuTables struct {
	spec clashSudokuTableSpec
	set  atomic.Pointer[clashSudokuTableSet]
}

func newClashSudokuTableSpec(seed string, tableType string, customTable string, customTables []string) (clashSudokuTableSpec, error) {
	if err := sudoku.ValidateClientTablePatterns(tableType, customTable, customTables); err != nil {
		return clashSudokuTableSpec{}, err
	}
	var patterns strings.Builder
	for _, pattern := range sudoku.ClientTablePatterns(customTable, customTables) {
		patterns.WriteString(strconv.Quote(pattern))
	}
	return clashSudokuTableSpec{
		key:          clashSudokuTableKey{seed: seed, tableType: tableType, patterns: patterns.String()},
		customTable:  customTable,
		customTables: customTables,
	}, nil
}

func (spec clashSudokuTableSpec) build() ([]*obfs.Table, error) {
	return sudoku.NewClientTablesWithCustomPatterns(spec.key.seed, spec.key.tableType, spec.customTable, spec.customTables)
}

var clashSudokuTablePresent obfs.Table

func (spec clashSudokuTableSpec) validate(conf sudoku.ProtocolConfig) error {
	conf.Table, conf.Tables = &clashSudokuTablePresent, nil
	return conf.Validate()
}

func (t *clashSudokuTables) fill(conf *sudoku.ProtocolConfig) error {
	set := t.set.Load()
	if set == nil {
		shared, err := clashSharedSudokuTables(t.spec)
		if err != nil {
			return fmt.Errorf("build table(s) failed: %w", err)
		}
		t.set.CompareAndSwap(nil, shared)
		set = t.set.Load()
	}
	if len(set.tables) == 1 {
		conf.Table = set.tables[0]
	} else {
		conf.Tables = set.tables
	}
	return nil
}

type clashSudokuTableSlot struct {
	key   clashSudokuTableKey
	ready chan struct{}
	set   weak.Pointer[clashSudokuTableSet]
	err   error
}

var clashSudokuTableCache struct {
	sync.Mutex
	slots map[clashSudokuTableKey]*clashSudokuTableSlot
}

var clashSudokuTableBuilds atomic.Int64

func clashSharedSudokuTables(spec clashSudokuTableSpec) (*clashSudokuTableSet, error) {
	for {
		clashSudokuTableCache.Lock()
		slot := clashSudokuTableCache.slots[spec.key]
		if slot == nil {
			slot = &clashSudokuTableSlot{key: spec.key, ready: make(chan struct{})}
			if clashSudokuTableCache.slots == nil {
				clashSudokuTableCache.slots = make(map[clashSudokuTableKey]*clashSudokuTableSlot)
			}
			clashSudokuTableCache.slots[spec.key] = slot
			clashSudokuTableCache.Unlock()
			return slot.fill(spec)
		}
		clashSudokuTableCache.Unlock()
		<-slot.ready
		if slot.err != nil {
			return nil, slot.err
		}
		if set := slot.set.Value(); set != nil {
			return set, nil
		}
		clashForgetSudokuTables(slot)
	}
}

func (slot *clashSudokuTableSlot) fill(spec clashSudokuTableSpec) (*clashSudokuTableSet, error) {
	defer close(slot.ready)
	clashSudokuTableBuilds.Add(1)
	tables, err := spec.build()
	if err != nil {
		slot.err = err
		clashForgetSudokuTables(slot)
		return nil, err
	}
	set := &clashSudokuTableSet{tables: tables}
	slot.set = weak.Make(set)
	runtime.AddCleanup(set, clashForgetSudokuTables, slot)
	return set, nil
}

func clashForgetSudokuTables(slot *clashSudokuTableSlot) {
	clashSudokuTableCache.Lock()
	if clashSudokuTableCache.slots[slot.key] == slot {
		delete(clashSudokuTableCache.slots, slot.key)
	}
	clashSudokuTableCache.Unlock()
}
