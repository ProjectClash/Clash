package clash

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/tunnel/statistic"
	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
	"github.com/sirupsen/logrus"
)

func TestCommandGettersReturnJSON(t *testing.T) {
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

	var status map[string]string
	if err := json.Unmarshal([]byte(StatusJSON()), &status); err != nil {
		t.Fatalf("StatusJSON invalid: %v", err)
	}
	if status["status"] != "running" {
		t.Fatalf("status = %q, want running", status["status"])
	}
	if status["mode"] == "" {
		t.Fatal("mode missing")
	}

	var traffic map[string]int64
	if err := json.Unmarshal([]byte(TrafficJSON()), &traffic); err != nil {
		t.Fatalf("TrafficJSON invalid: %v", err)
	}
	for _, k := range []string{"up", "down", "upTotal", "downTotal", "rateFresh", "rateSampledAtUnixMs"} {
		if _, ok := traffic[k]; !ok {
			t.Fatalf("traffic missing key %q", k)
		}
	}
	if fresh := traffic["rateFresh"]; fresh != 0 && fresh != 1 {
		t.Fatalf("rateFresh is %d, want 0 or 1", fresh)
	}

	var conns map[string]json.RawMessage
	if err := json.Unmarshal([]byte(ConnectionsJSON()), &conns); err != nil {
		t.Fatalf("ConnectionsJSON invalid: %v", err)
	}
	if _, ok := conns["connections"]; !ok {
		t.Fatal("connections key missing")
	}

	var ruleProviders map[string]json.RawMessage
	if err := json.Unmarshal([]byte(RuleProvidersJSON()), &ruleProviders); err != nil {
		t.Fatalf("RuleProvidersJSON invalid: %v", err)
	}
	if _, ok := ruleProviders["providers"]; !ok {
		t.Fatal("rule providers key missing")
	}

	var proxies struct {
		Proxies map[string]json.RawMessage `json:"proxies"`
	}
	if err := json.Unmarshal([]byte(ProxiesJSON()), &proxies); err != nil {
		t.Fatalf("ProxiesJSON invalid: %v", err)
	}
	if _, ok := proxies.Proxies["probe"]; !ok {
		t.Fatalf("proxies missing 'probe': got keys %v", keysOf(proxies.Proxies))
	}
}

func keysOf(m map[string]json.RawMessage) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}

func TestTrafficSaysWhetherItsRateIsCurrent(t *testing.T) {
	manager := statistic.DefaultManager
	manager.Now()
	deadline := time.Now().Add(3 * time.Second)
	var traffic map[string]int64
	for time.Now().Before(deadline) {
		if err := json.Unmarshal([]byte(TrafficJSON()), &traffic); err != nil {
			t.Fatalf("TrafficJSON invalid: %v", err)
		}
		if traffic["rateFresh"] == 1 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if traffic["rateFresh"] != 1 || traffic["rateSampledAtUnixMs"] == 0 {
		t.Fatalf("a running sampler's rate is not reported as current: %v", traffic)
	}
	if age := time.Since(time.UnixMilli(traffic["rateSampledAtUnixMs"])); age > 3*time.Second {
		t.Fatalf("rateSampledAtUnixMs is %s old for a running sampler", age)
	}
}

type fakeTrafficRates struct {
	up, down  int64
	sampledAt time.Time
	fresh     bool
}

func (f fakeTrafficRates) LastRate() (int64, int64, time.Time, bool) {
	return f.up, f.down, f.sampledAt, f.fresh
}

func (f fakeTrafficRates) Now() (int64, int64) {
	if !f.fresh {
		return 0, 0
	}
	return f.up, f.down
}

func (f fakeTrafficRates) Total() (int64, int64) { return 100, 200 }

func useTrafficRates(t *testing.T, source trafficRateSource) {
	t.Helper()
	previous := trafficRates
	trafficRates = source
	t.Cleanup(func() { trafficRates = previous })
}

func TestAStaleRateIsMarkedForTheWidgetAndZeroForREST(t *testing.T) {
	sampled := time.Now().Add(-10 * time.Minute)
	useTrafficRates(t, fakeTrafficRates{up: 7000, down: 9000, sampledAt: sampled, fresh: false})

	var traffic map[string]int64
	if err := json.Unmarshal([]byte(TrafficJSON()), &traffic); err != nil {
		t.Fatalf("TrafficJSON invalid: %v", err)
	}
	if traffic["up"] != 7000 || traffic["down"] != 9000 {
		t.Fatalf("the widget lost the last measured rate: %v", traffic)
	}
	if traffic["rateFresh"] != 0 || traffic["rateSampledAtUnixMs"] != sampled.UnixMilli() {
		t.Fatalf("a stale rate is not marked as such: %v", traffic)
	}

	recorder := httptest.NewRecorder()
	serveTrafficSnapshot(recorder, httptest.NewRequest(http.MethodGet, "/clash/v1/traffic", nil))
	var snapshot map[string]int64
	if err := json.Unmarshal(recorder.Body.Bytes(), &snapshot); err != nil {
		t.Fatalf("snapshot invalid: %v", err)
	}
	if snapshot["up"] != 0 || snapshot["down"] != 0 || snapshot["rateFresh"] != 0 {
		t.Fatalf("REST returned a stale rate as current: %v", snapshot)
	}

	useTrafficRates(t, fakeTrafficRates{up: 7000, down: 9000, sampledAt: time.Now(), fresh: true})
	if err := json.Unmarshal([]byte(TrafficJSON()), &traffic); err != nil || traffic["rateFresh"] != 1 {
		t.Fatalf("a current rate is not marked current: %v %v", traffic, err)
	}
	recorder = httptest.NewRecorder()
	serveTrafficSnapshot(recorder, httptest.NewRequest(http.MethodGet, "/clash/v1/traffic", nil))
	if err := json.Unmarshal(recorder.Body.Bytes(), &snapshot); err != nil || snapshot["up"] != 7000 || snapshot["rateFresh"] != 1 {
		t.Fatalf("REST did not return a current rate: %v %v", snapshot, err)
	}
}
