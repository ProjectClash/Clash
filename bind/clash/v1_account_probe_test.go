package clash

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"runtime/pprof"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/adapter"
	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/tunnel"
)

func TestV1AccountProbe(t *testing.T) {
	out := os.Getenv("CLASH_V1_ACCOUNT")
	if out == "" {
		t.Skip()
	}
	out, _ = filepath.Abs(out)
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatal(err)
	}
	switch os.Getenv("CLASH_V1_PHASE") {
	case "publish":
		v1Publish(t, out)
	case "run":
		v1Run(t, out)
	default:
		t.Fatal("CLASH_V1_PHASE is publish or run")
	}
}

const v1TestURL = "http://127.0.0.1:24480/generate_204"

func v1Document(nodes int) string {
	base := map[string]string{
		"HY2":    "type: hysteria2, server: 127.0.0.1, port: 24431, password: v1-pass, skip-cert-verify: true",
		"TUIC":   "type: tuic, server: 127.0.0.1, port: 24432, uuid: 00000000-0000-4000-8000-000000000001, password: v1-pass, congestion-controller: bbr, skip-cert-verify: true",
		"Trojan": "type: trojan, server: 127.0.0.1, port: 24433, password: v1-pass, skip-cert-verify: true",
	}
	kinds := []string{"HY2", "TUIC", "Trojan"}
	short := map[string]string{"HY2": "H", "TUIC": "T", "Trojan": "J"}
	var lines, names []string
	for _, k := range kinds {
		names = append(names, k)
		lines = append(lines, fmt.Sprintf("- {name: %s, %s}", k, base[k]))
	}
	copies := nodes - 3
	per := []int{copies / 3, copies / 3, copies / 3}
	for i := 0; i < copies%3; i++ {
		per[i]++
	}
	for i := 0; i < per[0]; i++ {
		for j, k := range kinds {
			if i < per[j] {
				name := short[k] + strconv.Itoa(i+1)
				names = append(names, name)
				lines = append(lines, fmt.Sprintf("- {name: %s, %s}", name, base[k]))
			}
		}
	}
	list := strings.Join(names, ", ")
	return strings.Join(append(append([]string{"mode: rule", "log-level: info", "proxies:"}, lines...),
		"proxy-groups:",
		"- {name: PROXY, type: select, proxies: [HY2, TUIC, Trojan, AUTO, FALLBACK]}",
		fmt.Sprintf("- {name: AUTO, type: url-test, url: %q, interval: 300, proxies: [%s]}", v1TestURL, list),
		fmt.Sprintf("- {name: FALLBACK, type: fallback, url: %q, interval: 300, proxies: [%s]}", v1TestURL, list),
		"rules:", "- DOMAIN-SUFFIX,lan-test.invalid,DIRECT", "- MATCH,PROXY", ""), "\n")
}

func v1Setup(t *testing.T, out string) *SetupOptions {
	setup := &SetupOptions{
		BasePath:       filepath.Join(out, "base"),
		WorkingPath:    filepath.Join(out, "base", "working"),
		TempPath:       filepath.Join(out, "base", "temp"),
		RuntimeProfile: RuntimeProfileIOSPacketTunnel,
		MemoryLimit:    50 << 20,
	}
	if err := Setup(setup); err != nil {
		t.Fatal(err)
	}
	C.SetHomeDir(setup.WorkingPath)
	return setup
}

func v1Publish(t *testing.T, out string) {
	nodes, err := strconv.Atoi(os.Getenv("CLASH_V1_NODES"))
	if err != nil || nodes < 3 {
		t.Fatal("CLASH_V1_NODES is 3 or more")
	}
	_ = os.RemoveAll(filepath.Join(out, "base"))
	setup := v1Setup(t, out)
	resources, _ := json.Marshal(map[string]any{"nodeLibraryDirectory": filepath.Join(setup.WorkingPath, "nodes")})
	finalized, err := FinalizeForIOS(v1Document(nodes), string(resources))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out, "published.yaml"), []byte(finalized.Value), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Logf("published %d nodes, %d bytes", nodes, len(finalized.Value))
}

type v1Sample struct {
	At           float64 `json:"at"`
	Footprint    int64   `json:"footprint"`
	HeapInuse    uint64  `json:"heapInuse"`
	HeapAlloc    uint64  `json:"heapAlloc"`
	HeapIdle     uint64  `json:"heapIdle"`
	HeapReleased uint64  `json:"heapReleased"`
	StackInuse   uint64  `json:"stackInuse"`
	Sys          uint64  `json:"sys"`
	OtherSys     uint64  `json:"otherSys"`
	MSpanInuse   uint64  `json:"mspanInuse"`
	GCSys        uint64  `json:"gcSys"`
	Goroutines   int     `json:"goroutines"`
}

func v1Read(began time.Time) v1Sample {
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	return v1Sample{
		At: time.Since(began).Seconds(), Footprint: physFootprint(),
		HeapInuse: stats.HeapInuse, HeapAlloc: stats.HeapAlloc, HeapIdle: stats.HeapIdle, HeapReleased: stats.HeapReleased,
		StackInuse: stats.StackInuse, Sys: stats.Sys, OtherSys: stats.OtherSys, MSpanInuse: stats.MSpanInuse, GCSys: stats.GCSys,
		Goroutines: runtime.NumGoroutine(),
	}
}

func v1Run(t *testing.T, out string) {
	rate, _ := strconv.Atoi(os.Getenv("CLASH_V1_PROFILE"))
	runtime.MemProfileRate = rate
	idle := 120
	if s, err := strconv.Atoi(os.Getenv("CLASH_V1_IDLE")); err == nil && s > 0 {
		idle = s
	}
	published, err := os.ReadFile(filepath.Join(out, "published.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	v1Setup(t, out)
	service, err := NewService(newRecordingPlatform())
	if err != nil {
		t.Fatal(err)
	}
	began := time.Now()
	if err := service.Start(string(published)); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = service.Close() }()
	if err := SelectProxy("PROXY", "HY2"); err != nil {
		t.Fatal(err)
	}
	var samples []v1Sample
	for time.Since(began) < time.Duration(idle)*time.Second {
		samples = append(samples, v1Read(began))
		time.Sleep(5 * time.Second)
	}
	if os.Getenv("CLASH_V1_SWEEP") != "" {
		if nodes, ok := tunnel.ProxyLibrary().(*adapter.LibraryNodes); ok {
			before := nodes.LiveCount()
			nodes.Sweep()
			t.Logf("swept: %d nodes held objects, %d after", before, nodes.LiveCount())
		}
	}
	if os.Getenv("CLASH_V1_PURGE") != "" {
		procs := runtime.GOMAXPROCS(1)
		runtime.GC()
		runtime.GOMAXPROCS(procs)
	}
	runtime.GC()
	debug.FreeOSMemory()
	samples = append(samples, v1Read(began))
	encoded, _ := json.MarshalIndent(samples, "", " ")
	name := "memstats.json"
	if rate > 0 {
		name = "memstats-profiled.json"
	}
	if err := os.WriteFile(filepath.Join(out, name), encoded, 0o644); err != nil {
		t.Fatal(err)
	}
	if rate > 0 {
		if f, err := os.Create(filepath.Join(out, "heap.pprof")); err == nil {
			_ = pprof.Lookup("heap").WriteTo(f, 0)
			_ = f.Close()
		}
		if f, err := os.Create(filepath.Join(out, "goroutines.txt")); err == nil {
			_ = pprof.Lookup("goroutine").WriteTo(f, 1)
			_ = f.Close()
		}
	}
	last := samples[len(samples)-1]
	t.Logf("t=%.0fs footprint %.2f MiB heapInuse %.2f stackInuse %.2f goroutines %d", last.At, float64(last.Footprint)/(1<<20), float64(last.HeapInuse)/(1<<20), float64(last.StackInuse)/(1<<20), last.Goroutines)
}
