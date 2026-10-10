package clash

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	C "github.com/ProjectClash/Clash/constant"

	"github.com/sirupsen/logrus"
)

const testMiB = int64(1 << 20)

func TestReloadMemoryJudgeRefusesTheProfileThatDied(t *testing.T) {
	verdict := judgeReloadMemory(reloadMemoryReading{
		AvailableBytes: 18*testMiB + testMiB/2,
		FootprintBytes: 31*testMiB + testMiB/2,
		BaselineBytes:  7*testMiB + 7*testMiB/10,
	}, 100_000, 100_000)
	if verdict.Reason != reloadRefusedMemory {
		t.Fatalf("reason = %q, want %q (%+v)", verdict.Reason, reloadRefusedMemory, verdict)
	}
	if verdict.NeededBytes <= verdict.AvailableBytes {
		t.Fatalf("a refusal must show needed > available, got %+v", verdict)
	}
	if verdict.FootprintBytes != 31*testMiB+testMiB/2 || verdict.AvailableBytes != 18*testMiB+testMiB/2 {
		t.Fatalf("the verdict must carry the readings it judged on, got %+v", verdict)
	}
}

func TestReloadMemoryJudgeAcceptsTheLightProfile(t *testing.T) {
	verdict := judgeReloadMemory(reloadMemoryReading{
		AvailableBytes: 36 * testMiB,
		FootprintBytes: 14 * testMiB,
		BaselineBytes:  7*testMiB + 7*testMiB/10,
	}, 100_000, 100_000)
	if verdict.Reason != reloadAccepted {
		t.Fatalf("reason = %q, want %q (%+v)", verdict.Reason, reloadAccepted, verdict)
	}
	if verdict.NeededBytes <= 0 || verdict.NeededBytes >= verdict.AvailableBytes {
		t.Fatalf("an acceptance still records what it thought it needed, got %+v", verdict)
	}
}

func TestReloadMemoryJudgeScalesUpWithTheCandidateAndNeverDown(t *testing.T) {
	reading := reloadMemoryReading{AvailableBytes: 30 * testMiB, FootprintBytes: 20 * testMiB, BaselineBytes: 8 * testMiB}
	same := judgeReloadMemory(reading, 100_000, 100_000)
	bigger := judgeReloadMemory(reading, 100_000, 200_000)
	smaller := judgeReloadMemory(reading, 100_000, 50_000)
	if bigger.NeededBytes <= same.NeededBytes {
		t.Fatalf("a candidate twice the size must need more: same %d, bigger %d", same.NeededBytes, bigger.NeededBytes)
	}
	if smaller.NeededBytes != same.NeededBytes {
		t.Fatalf("a smaller candidate must not lower the estimate: same %d, smaller %d", same.NeededBytes, smaller.NeededBytes)
	}
}

func TestReloadMemoryJudgeOnlyJudgesAStrictlyPositiveReading(t *testing.T) {
	heavy := func(available int64) reloadMemoryVerdict {
		return judgeReloadMemory(reloadMemoryReading{
			AvailableBytes: available, FootprintBytes: 40 * testMiB, BaselineBytes: 8 * testMiB,
		}, 100_000, 100_000)
	}
	if verdict := heavy(1); verdict.Reason != reloadRefusedMemory {
		t.Fatalf("1 byte of headroom is a reading and a heavy profile must be refused on it, got %+v", verdict)
	}
	for _, available := range []int64{0, -1} {
		if verdict := heavy(available); verdict.Reason != reloadUnmeasured {
			t.Fatalf("available=%d is not a reading; reason = %q, want %q", available, verdict.Reason, reloadUnmeasured)
		}
	}
	verdict := judgeReloadMemory(reloadMemoryReading{AvailableBytes: 10 * testMiB, FootprintBytes: -1, BaselineBytes: 8 * testMiB}, 1, 1)
	if verdict.Reason != reloadUnmeasured {
		t.Fatalf("no footprint reading must be unmeasured, got %+v", verdict)
	}
}

func TestReloadRefusesUnderTheMemoryCeilingWithoutBuildingASecondCore(t *testing.T) {
	t.Cleanup(func() { logrus.SetOutput(os.Stdout) })
	if err := Setup(testOptions(t)); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	svc, err := NewService(newRecordingPlatform())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	if err := svc.Start(helloYAML); err != nil {
		t.Fatalf("Start: %v", err)
	}
	restore := fakeReloadMemoryReaders(t, 18*testMiB+testMiB/2, 31*testMiB+testMiB/2)
	defer restore()
	svc.startFootprintBytes = 7*testMiB + 7*testMiB/10

	err = svc.Reload("mode: [broken")
	if err == nil {
		t.Fatal("a reload that would exceed the ceiling must be refused")
	}
	if !strings.HasPrefix(err.Error(), "clash: reload refused (memory): need ~") ||
		!strings.HasSuffix(err.Error(), "; restart the appex instead") {
		t.Fatalf("refusal sentence = %q; want the (memory) token and the restart tail, not a parse error", err.Error())
	}
	if !svc.running {
		t.Fatal("a refused reload leaves the service running")
	}
	verdict := recordedReloadVerdict(svc)
	if verdict.Reason != reloadRefusedMemory || verdict.NeededBytes == 0 || verdict.AvailableBytes != 18*testMiB+testMiB/2 {
		t.Fatalf("the diagnostics must carry the refusal in numbers, got %+v", verdict)
	}

	restore()
	restore = fakeReloadMemoryReaders(t, 36*testMiB, 14*testMiB)
	if err := svc.Reload(helloYAML + "\n"); err != nil {
		t.Fatalf("a reload that fits must go through: %v", err)
	}
	if verdict := recordedReloadVerdict(svc); verdict.Reason != reloadAccepted {
		t.Fatalf("an accepted reload records its verdict too, got %+v", verdict)
	}
}

func fakeReloadMemoryReaders(t *testing.T, available, footprint int64) func() {
	t.Helper()
	previousAvailable, previousFootprint := readAvailableMemoryForReload, readFootprintForReload
	readAvailableMemoryForReload = func() int64 { return available }
	readFootprintForReload = func() int64 { return footprint }
	restore := func() {
		readAvailableMemoryForReload, readFootprintForReload = previousAvailable, previousFootprint
	}
	t.Cleanup(restore)
	return restore
}

func recordedReloadVerdict(svc *BoxService) reloadMemoryVerdict {
	svc.mu.Lock()
	defer svc.mu.Unlock()
	return svc.reloadVerdict
}

func TestRuntimeDiagnosticsCarryTheLastReloadVerdict(t *testing.T) {
	t.Cleanup(func() { logrus.SetOutput(os.Stdout) })
	if err := Setup(testOptions(t)); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	svc, err := NewService(newRecordingPlatform())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	if err := svc.Start(helloYAML); err != nil {
		t.Fatalf("Start: %v", err)
	}
	var before map[string]any
	if err := json.Unmarshal([]byte(svc.RuntimeDiagnosticsJSON()), &before); err != nil {
		t.Fatalf("diagnostics before any reload: %v", err)
	}
	if _, present := before["reloadVerdict"]; present {
		t.Fatalf("no reload has been judged yet, but diagnostics carry %v", before["reloadVerdict"])
	}

	fakeReloadMemoryReaders(t, 18*testMiB+testMiB/2, 31*testMiB+testMiB/2)
	svc.startFootprintBytes = 7*testMiB + 7*testMiB/10
	if err := svc.Reload(helloYAML + "\n"); err == nil {
		t.Fatal("the heavy numbers must refuse")
	}
	var after map[string]any
	if err := json.Unmarshal([]byte(svc.RuntimeDiagnosticsJSON()), &after); err != nil {
		t.Fatalf("diagnostics after the refusal: %v", err)
	}
	verdict, ok := after["reloadVerdict"].(map[string]any)
	if !ok {
		t.Fatalf("diagnostics must carry reloadVerdict as an object, got %v", after["reloadVerdict"])
	}
	if verdict["reason"] != reloadRefusedMemory {
		t.Fatalf("reloadVerdict.reason = %v, want %q", verdict["reason"], reloadRefusedMemory)
	}
	for _, key := range []string{"neededBytes", "availableBytes", "footprintBytes", "atUnix"} {
		if number, ok := verdict[key].(float64); !ok || number <= 0 {
			t.Fatalf("reloadVerdict.%s must be a positive number, got %v", key, verdict[key])
		}
	}
}

func TestReloadMemoryJudgeReadsAZeroByThePlatformsOwnMeaning(t *testing.T) {
	onIOS := judgeReloadMemory(reloadMemoryReading{
		AvailableBytes: 0, FootprintBytes: 20 * testMiB, BaselineBytes: 8 * testMiB, ZeroMeansExhausted: true,
	}, 100, 100)
	if onIOS.Reason != reloadRefusedMemory {
		t.Fatalf("zero headroom where zero means exhausted must refuse, got %+v", onIOS)
	}
	if onIOS.AvailableBytes != 0 || onIOS.NeededBytes <= 0 {
		t.Fatalf("the refusal must still carry the numbers (need > 0, have 0), got %+v", onIOS)
	}
	onMac := judgeReloadMemory(reloadMemoryReading{
		AvailableBytes: 0, FootprintBytes: 20 * testMiB, BaselineBytes: 8 * testMiB, ZeroMeansExhausted: false,
	}, 100, 100)
	if onMac.Reason != reloadUnmeasured {
		t.Fatalf("zero where zero means no reading must stay unmeasured, got %+v", onMac)
	}
	blind := judgeReloadMemory(reloadMemoryReading{AvailableBytes: 0, FootprintBytes: -1, ZeroMeansExhausted: true}, 1, 1)
	if blind.Reason != reloadRefusedMemory {
		t.Fatalf("exhausted with no footprint reading must still refuse, got %+v", blind)
	}
	if v := judgeReloadMemory(reloadMemoryReading{AvailableBytes: -1, FootprintBytes: 20 * testMiB, ZeroMeansExhausted: true}, 1, 1); v.Reason != reloadUnmeasured {
		t.Fatalf("-1 must stay unmeasured, got %+v", v)
	}
}

func TestReloadRefusesOnZeroHeadroomWhereZeroMeansExhausted(t *testing.T) {
	t.Cleanup(func() { logrus.SetOutput(os.Stdout) })
	if err := Setup(testOptions(t)); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	svc, err := NewService(newRecordingPlatform())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	if err := svc.Start(helloYAML); err != nil {
		t.Fatalf("Start: %v", err)
	}
	fakeReloadMemoryReaders(t, 0, 20*testMiB)
	previousMeaning := zeroHeadroomMeansExhausted
	zeroHeadroomMeansExhausted = true
	t.Cleanup(func() { zeroHeadroomMeansExhausted = previousMeaning })

	err = svc.Reload("mode: [broken")
	if err == nil || !strings.HasPrefix(err.Error(), "clash: reload refused (memory): need ~") || !strings.Contains(err.Error(), ", have 0 MiB; restart the appex instead") {
		t.Fatalf("zero headroom on iOS must refuse before parsing with have 0 MiB, got %v", err)
	}
	zeroHeadroomMeansExhausted = false
	err = svc.Reload("mode: [broken")
	if err == nil || strings.HasPrefix(err.Error(), "clash: reload refused (memory)") {
		t.Fatalf("zero headroom on darwin must not refuse; got %v", err)
	}
}

func TestReloadMemoryJudgeCountsProviderPayloadGrowth(t *testing.T) {
	base := reloadMemoryReading{AvailableBytes: 30 * testMiB, FootprintBytes: 16 * testMiB, BaselineBytes: 8 * testMiB}
	same := judgeReloadMemory(base, 100, 100)
	if same.Reason != reloadAccepted {
		t.Fatalf("baseline case must be accepted, got %+v", same)
	}
	grown := base
	grown.CurrentProviderBytes, grown.CandidateProviderBytes = 1*testMiB, 16*testMiB
	verdict := judgeReloadMemory(grown, 100, 100)
	if verdict.Reason != reloadRefusedMemory {
		t.Fatalf("a provider growing by 15 MiB into 30 MiB of headroom on a 16 MiB core must refuse, got %+v", verdict)
	}
	if verdict.NeededBytes < same.NeededBytes+2*15*testMiB {
		t.Fatalf("growth must be counted twice (raw + prepared): needed %d, want >= %d", verdict.NeededBytes, same.NeededBytes+2*15*testMiB)
	}
	shrunk := base
	shrunk.CurrentProviderBytes, shrunk.CandidateProviderBytes = 16*testMiB, 1*testMiB
	if v := judgeReloadMemory(shrunk, 100, 100); v.NeededBytes != same.NeededBytes {
		t.Fatalf("shrinkage must not be credited: needed %d, want %d", v.NeededBytes, same.NeededBytes)
	}
}

func TestProviderPayloadBytesSumsTheFilesBehindTheProviders(t *testing.T) {
	if err := Setup(testOptions(t)); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	rules := filepath.Join(dir, "rules.yaml")
	proxies := filepath.Join(dir, "proxies.yaml")
	if err := os.WriteFile(rules, make([]byte, 3000), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(proxies, make([]byte, 5000), 0o600); err != nil {
		t.Fatal(err)
	}
	yaml := "mode: rule\nproxy-providers:\n  p:\n    type: file\n    path: " + proxies + "\nrule-providers:\n  r:\n    type: file\n    behavior: domain\n    path: " + rules + "\n  missing:\n    type: file\n    behavior: domain\n    path: " + filepath.Join(dir, "absent.yaml") + "\nrules:\n  - MATCH,DIRECT\n"
	if got := providerPayloadBytes(yaml); got != 8000 {
		t.Fatalf("providerPayloadBytes = %d, want 8000 (3000 + 5000, the missing file counts zero)", got)
	}
	if got := providerPayloadBytes("mode: [broken"); got != 0 {
		t.Fatalf("unreadable YAML must count zero, got %d", got)
	}
}

func TestProviderPayloadBytesReadsKeysTheWayThePipelineDoes(t *testing.T) {
	if err := Setup(testOptions(t)); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	file := filepath.Join(dir, "rules.yaml")
	if err := os.WriteFile(file, make([]byte, 4096), 0o600); err != nil {
		t.Fatal(err)
	}
	yaml := "mode: rule\nrule-providers:\n  r:\n    type: file\n    behavior: domain\n    Path: " + file + "\nrules:\n  - MATCH,DIRECT\n"
	if got := providerPayloadBytes(yaml); got != 4096 {
		t.Fatalf("providerPayloadBytes with a `Path:` spelling = %d, want 4096", got)
	}

	missing := filepath.Join(dir, "absent.yaml")
	both := "mode: rule\nrule-providers:\n  r:\n    type: file\n    behavior: domain\n    path: " + file + "\n    Path: " + missing + "\nrules:\n  - MATCH,DIRECT\n"
	for round := 0; round < 8; round++ {
		if got := providerPayloadBytes(both); got != 4096 {
			t.Fatalf("round %d: with `path:` present the pipeline loads it, but the estimator read %d bytes (the `Path:` duplicate)", round, got)
		}
	}
	small := filepath.Join(dir, "small.yaml")
	if err := os.WriteFile(small, make([]byte, 100), 0o600); err != nil {
		t.Fatal(err)
	}
	mixed := "mode: rule\nrule-providers:\n  r:\n    type: file\n    behavior: domain\n    Path: " + small + "\n    PATH: " + file + "\nrules:\n  - MATCH,DIRECT\n"
	for round := 0; round < 8; round++ {
		if got := providerPayloadBytes(mixed); got != 4096 {
			t.Fatalf("round %d: with no lowercase key the estimator must charge the largest variant, got %d", round, got)
		}
	}
	precedence := "mode: rule\nrule-providers:\n  r:\n    type: file\n    behavior: domain\n    path: " + small + "\n    Path: " + file + "\nrules:\n  - MATCH,DIRECT\n"
	for round := 0; round < 8; round++ {
		if got := providerPayloadBytes(precedence); got != 100 {
			t.Fatalf("round %d: `path:` names the 100-byte file and the pipeline loads exactly it, but the estimator charged %d", round, got)
		}
	}

	empty := filepath.Join(dir, "empty.yaml")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	staleURL := "https://example.invalid/rules.yaml"
	stale := C.Path.GetPathByHash("rules", staleURL)
	if err := os.MkdirAll(filepath.Dir(stale), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stale, make([]byte, 8192), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(stale) })
	zeroWithURL := "mode: rule\nrule-providers:\n  r:\n    type: file\n    behavior: domain\n    path: " + empty + "\n    url: " + staleURL + "\nrules:\n  - MATCH,DIRECT\n"
	if got := providerPayloadBytes(zeroWithURL); got != 0 {
		t.Fatalf("a declared zero-byte path must charge zero; the estimator charged %d (the url's stale cache)", got)
	}
	urlOnly := "mode: rule\nrule-providers:\n  r:\n    type: http\n    behavior: domain\n    url: " + staleURL + "\nrules:\n  - MATCH,DIRECT\n"
	if got := providerPayloadBytes(urlOnly); got != 8192 {
		t.Fatalf("with only a url the hashed cache is the payload, got %d want 8192", got)
	}
}

func TestProviderGrowthIsChargedAtTheMeasuredExpansion(t *testing.T) {
	base := reloadMemoryReading{AvailableBytes: 40 * testMiB, FootprintBytes: 12 * testMiB, BaselineBytes: 8 * testMiB}
	same := judgeReloadMemory(base, 100, 100)
	grown := base
	grown.CurrentProviderBytes, grown.CandidateProviderBytes = 0, 4_700_000
	verdict := judgeReloadMemory(grown, 100, 100)
	if delta := verdict.NeededBytes - same.NeededBytes; delta < 25*testMiB {
		t.Fatalf("4.7 MB of provider growth charged %d bytes; the tree's own measurement is at least 25 MiB", delta)
	}
}
