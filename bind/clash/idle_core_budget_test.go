package clash

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/metrics"
	"runtime/pprof"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const (
	idleCoreHeapBudget       = 768 << 10
	idleCoreGoroutinesBudget = 50
)

const subscriptionExcludeFilter = `(?i)(群|返利|循环|官网|客服|网站|网址|获取|订阅|流量|到期|机场|下次|版本|官址|过期|已用|联系|邮箱|工单|贩卖|通知|倒卖|防止|国内|地址|电报|频道|无法|说明|提示|访问|支持|教程|关注|更新|作者|加入|超时|收藏|优惠|福利|邀请|好友|失联|选择|剩余|公益|发布|DIZTNA|通路|登录|定时|渠道|牢记|永久|余额|阁下|本站|刷新|导航|建议|重置|以下|过滤|⚠️|@|t\.me\/\+|\bexpire\b|\bhttps?:\/\/|\.com|\btraffic\b)`

func idleCoreBudgetConfig() string {
	var b strings.Builder
	b.WriteString("mode: rule\nlog-level: info\n")
	b.WriteString("dns:\n  enable: true\n  enhanced-mode: fake-ip\n  fake-ip-range: 198.18.0.1/16\n  nameserver: ['223.5.5.5']\n")
	b.WriteString("tun:\n  enable: true\n  stack: mips\n")
	b.WriteString("proxies:\n")
	regions := []string{"香港", "日本", "美国", "新加坡", "台湾"}
	for i := 0; i < 10; i++ {
		fmt.Fprintf(&b, "  - {name: '%s %02d', type: direct}\n", regions[i%len(regions)], i)
	}
	b.WriteString("proxy-groups:\n")
	for i := 0; i < 40; i++ {
		fmt.Fprintf(&b, "  - {name: 'group %02d', type: url-test, include-all: true, lazy: true, interval: 600, "+
			"url: 'http://127.0.0.1:1/never', filter: '(?i)(%s|HK)', exclude-filter: '%s'}\n",
			i, regions[i%len(regions)], strings.ReplaceAll(subscriptionExcludeFilter, "'", "''"))
	}
	b.WriteString("rules:\n")
	for i := 0; i < 40; i++ {
		fmt.Fprintf(&b, "  - DOMAIN-SUFFIX,example%02d.com,group %02d\n", i, i)
	}
	b.WriteString("  - MATCH,DIRECT\n")
	return b.String()
}

func liveHeapAfterCollections() uint64 {
	runtime.GC()
	runtime.GC()
	sample := []metrics.Sample{{Name: "/gc/heap/live:bytes"}}
	metrics.Read(sample)
	return sample[0].Value.Uint64()
}

func TestTheIdleCoreStaysWithinItsBudget(t *testing.T) {
	disarmThresholdMonitor(t, pressureThresholdShedEnabled.Load())
	base, err := os.MkdirTemp("/tmp", "clash-idle-budget-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	if err := Setup(&SetupOptions{BasePath: base, WorkingPath: filepath.Join(base, "w"), TempPath: filepath.Join(base, "t")}); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	finalized, err := FinalizeForIOS(idleCoreBudgetConfig(), "{}")
	if err != nil {
		t.Fatalf("finalize: %v", err)
	}
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fds[1])
	platform := &fdPlatform{recordingPlatform: recordingPlatform{lines: make(chan string, 4096), underNetworkExtension: true}, fd: int32(fds[0])}
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		for range platform.lines {
		}
	}()
	svc, err := NewService(platform)
	if err != nil {
		t.Fatal(err)
	}
	heapBefore, goroutinesBefore := liveHeapAfterCollections(), runtime.NumGoroutine()
	if err := svc.Start(finalized.Value); err != nil {
		t.Fatalf("Start: %v", err)
	}
	time.Sleep(3 * time.Second)
	heap, goroutines := liveHeapAfterCollections()-heapBefore, runtime.NumGoroutine()-goroutinesBefore
	if path := os.Getenv("CLASH_IDLE_BUDGET_GOROUTINES"); path != "" {
		f, _ := os.Create(path)
		_ = pprof.Lookup("goroutine").WriteTo(f, 1)
		_ = f.Close()
	}
	if err := svc.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	t.Logf("the idle core keeps %d KiB of live heap (budget %d KiB) and %d goroutines (budget %d)",
		heap>>10, idleCoreHeapBudget>>10, goroutines, idleCoreGoroutinesBudget)
	if heap > idleCoreHeapBudget {
		t.Errorf("the idle core keeps %d KiB of live heap, over its %d KiB budget: find what a change made it keep (a heap profile of this configuration, go tool pprof -sample_index=inuse_space)", heap>>10, idleCoreHeapBudget>>10)
	}
	if goroutines > idleCoreGoroutinesBudget {
		t.Errorf("the idle core runs %d goroutines, over its budget of %d", goroutines, idleCoreGoroutinesBudget)
	}
}
