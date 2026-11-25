package clashindex_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	C "github.com/ProjectClash/Clash/constant"
	R "github.com/ProjectClash/Clash/rules"
	"github.com/ProjectClash/Clash/rules/clashindex"
	RC "github.com/ProjectClash/Clash/rules/common"
)


var writtenLines = []string{
	"DOMAIN-SUFFIX,Shared.Example,REJECT",
	"DOMAIN,WWW.Example.com,A",
	"DOMAIN-KEYWORD,KwMod,B",
	"IP-CIDR6,2001:db8::/32,C,no-resolve",
	"IP-CIDR,192.0.2.0/24,REJECT,no-resolve",
	"DST-PORT,8443,DIRECT",
	"AND,((NETWORK,UDP),(DST-PORT,443)),REJECT",
}

func compileWritten(t *testing.T, lines []string, subRules map[string][]C.Rule, keep bool) []byte {
	t.Helper()
	compiler := clashindex.NewCompiler()
	if keep {
		compiler.KeepWritten()
	}
	for _, line := range lines {
		tp, payload, target, params := RC.ParseRulePayload(line, true)
		rule, err := R.ParseRule(tp, payload, target, params, subRules)
		if err != nil {
			t.Fatalf("%s: %v", line, err)
		}
		if err := compiler.Add(line, rule); err != nil {
			t.Fatal(err)
		}
	}
	var buffer bytes.Buffer
	if _, _, err := compiler.Write(&buffer); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func tableOf(t *testing.T, data []byte, subRules map[string][]C.Rule) (*clashindex.Index, *clashindex.Table) {
	t.Helper()
	index, err := clashindex.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	var others []C.Rule
	index.Others(func(_ int, line string) bool {
		tp, payload, target, params := RC.ParseRulePayload(line, true)
		rule, err := R.ParseRule(tp, payload, target, params, subRules)
		if err != nil {
			t.Fatal(err)
		}
		others = append(others, rule)
		return true
	})
	table, err := index.Table(others)
	if err != nil {
		t.Fatal(err)
	}
	return index, table
}

func TestAnIndexKeepingTheLinesWrittenReadsEachAsItWasWritten(t *testing.T) {
	c := newCorpus(t, 22, 2000, 5, 0)
	lines := append(append([]string{}, writtenLines...), c.lines...)
	keptData, plainData := compileWritten(t, lines, c.subRules, true), compileWritten(t, lines, c.subRules, false)
	if v := binary.LittleEndian.Uint32(keptData[8:]); v != 2 {
		t.Fatalf("an index keeping its lines is version %d, want 2", v)
	}
	if v := binary.LittleEndian.Uint32(plainData[8:]); v != 1 {
		t.Fatalf("an index not keeping them is version %d, want 1", v)
	}
	kept, keptTable := tableOf(t, keptData, c.subRules)
	plain, plainTable := tableOf(t, plainData, c.subRules)
	if !kept.KeepsWritten() || plain.KeepsWritten() {
		t.Fatalf("KeepsWritten: %v kept, %v not", kept.KeepsWritten(), plain.KeepsWritten())
	}
	for i, line := range lines {
		got, mapped, ok := kept.Written(i)
		_, wasMapped, _ := plain.Written(i)
		if !ok || got != line || mapped != wasMapped {
			t.Fatalf("rule %d: %q (mapped %v, %v), want %q as written (mapped %v)", i, got, mapped, ok, line, wasMapped)
		}
		tp, target, isMapped := kept.MappedTypeAndTarget(i)
		tp2, target2, isMapped2 := plain.MappedTypeAndTarget(i)
		if tp != tp2 || target != target2 || isMapped != isMapped2 {
			t.Fatalf("rule %d's type and target: %s %s %v, want %s %s %v", i, tp, target, isMapped, tp2, target2, isMapped2)
		}
	}
	if line, _, _ := plain.Written(0); line != "DOMAIN-SUFFIX,shared.example,REJECT" {
		t.Fatalf("an index not keeping its lines writes rule 0 as %q, as it always did", line)
	}
	first := func(table *clashindex.Table, m C.Metadata) int {
		at := -1
		table.Walk(&m, C.RuleMatchHelper{}, nil, func(i int, _ C.Rule, _ string) bool { at = i; return true })
		return at
	}
	for _, m := range c.queries(7, 500) {
		if a, b := first(keptTable, m), first(plainTable, m); a != b {
			t.Fatalf("%+v: rule %d keeping the lines, %d not", m, a, b)
		}
	}
}

func TestAnIndexNotKeepingTheLinesIsTheBytesItWas(t *testing.T) {
	_, data := newCorpus(t, 21, 5000, 5, 0).compile(t, false)
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != "b3032471df7dd2fff46242efa0b5a07fe9520157a6c55e3dc3cab6f9e2ea3b7d" || len(data) != 231752 {
		t.Fatalf("the index is %s, %d bytes: not the bytes a tunnel opens now", got, len(data))
	}
}

func TestAnIndexKeepingTheLinesChecksThem(t *testing.T) {
	data := compileWritten(t, writtenLines, nil, true)
	const sectionsAt, writtenRules = 8 + 4*4 + 32, 16
	at := binary.LittleEndian.Uint32(data[sectionsAt+8*writtenRules:])
	for _, field := range []uint32{0, 4} {
		damaged := append([]byte(nil), data...)
		binary.LittleEndian.PutUint32(damaged[at+field:], 1<<30)
		sum := sha256.Sum256(damaged[:len(damaged)-32])
		copy(damaged[len(damaged)-32:], sum[:])
		if _, err := clashindex.Decode(damaged); err == nil {
			t.Fatalf("a line kept at a place past the lines decoded (field %d)", field)
		}
	}
	if _, err := clashindex.Decode(data); err != nil {
		t.Fatal(err)
	}
}

func TestThreeIndexesOpenedInTurnAreEachMappedOnce(t *testing.T) {
	dir := t.TempDir()
	var paths []string
	var sums [][32]byte
	for i, keep := range []bool{false, true, true} {
		data := compileWritten(t, append([]string{fmt.Sprintf("DOMAIN,n%d.example,DIRECT", i)}, writtenLines...), nil, keep)
		path := filepath.Join(dir, fmt.Sprintf("rules-%d.index", i))
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, path)
		sums = append(sums, [32]byte(data[len(data)-32:]))
	}
	first := make([]*clashindex.Index, len(paths))
	for round := 0; round < 3; round++ {
		for i, path := range paths {
			index, err := clashindex.OpenVerified(path, sums[i])
			if err != nil {
				t.Fatal(err)
			}
			if round == 0 {
				first[i] = index
			} else if index != first[i] {
				t.Fatalf("round %d: index %d was mapped again after the others were opened", round, i)
			}
		}
	}
}

func TestAnIndexSaysWhichOfItsRulesANameAloneDecides(t *testing.T) {
	_, table := tableOf(t, compileWritten(t, writtenLines, nil, true), nil)
	for i, want := range []bool{true, true, true, false, false, false, false} {
		if got := table.ClashNamedOnly(i); got != want {
			t.Errorf("rule %d (%s): named only %v, want %v", i, writtenLines[i], got, want)
		}
	}
}
