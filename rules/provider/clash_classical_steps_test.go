package provider

import (
	"fmt"
	"runtime"
	"testing"

	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/rules/common"
)


func ipCIDROnly(tp, payload, target string, params []string, _ map[string][]C.Rule) (C.Rule, error) {
	if tp != "IP-CIDR" {
		return nil, fmt.Errorf("not parsed here: %s", tp)
	}
	return common.NewIPCIDR(payload, target, common.WithIPCIDRNoResolve(len(params) > 0 && params[0] == "no-resolve"))
}

func mergedIPLines(n int) []string {
	lines := make([]string, n)
	for i := range lines {
		lines[i] = fmt.Sprintf("IP-CIDR,10.%d.%d.0/25,no-resolve", i/256, i%256)
	}
	return lines
}

func TestMergedIPLinesLeaveNoRoomForAStepPerLine(t *testing.T) {
	const n = 20000
	lines := mergedIPLines(n)
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	s := NewClassicalStrategy(ipCIDROnly)
	for _, line := range lines {
		s.Insert(line)
	}
	s.FinishInsert()
	runtime.GC()
	runtime.ReadMemStats(&after)
	perLine := (int64(after.HeapAlloc) - int64(before.HeapAlloc)) / n
	t.Logf("%d merged IP lines: %d step(s), room for %d; %d B of live heap a line", n, len(s.steps), cap(s.steps), perLine)
	if !s.indexed || len(s.steps) != 1 || s.Count() != n {
		t.Fatalf("indexed %v, %d steps, count %d: the run did not become one set", s.indexed, len(s.steps), s.Count())
	}
	if cap(s.steps) != len(s.steps) {
		t.Errorf("the steps keep room for %d, hold %d", cap(s.steps), len(s.steps))
	}
	if perLine > 56 {
		t.Errorf("a merged IP line holds %d B; the set's range is 48 B", perLine)
	}
	runtime.KeepAlive(s)
	runtime.KeepAlive(lines)
}

func TestUnmergedStepsKeepTheirOrderAndNoRoom(t *testing.T) {
	s := NewClassicalStrategy(ipCIDROnly)
	for _, line := range []string{"IP-CIDR,10.0.0.0/8,no-resolve", "IP-CIDR,192.168.0.0/16", "IP-CIDR,172.16.0.0/12,no-resolve"} {
		s.Insert(line)
	}
	s.FinishInsert()
	if len(s.steps) != 3 || cap(s.steps) != 3 {
		t.Fatalf("%d steps with room for %d, want 3 and 3", len(s.steps), cap(s.steps))
	}
	for i, want := range []int{0, 1, 2} {
		if s.steps[i].line != want || s.steps[i].cidrs == nil {
			t.Fatalf("step %d: line %d, set %v", i, s.steps[i].line, s.steps[i].cidrs != nil)
		}
	}
}
