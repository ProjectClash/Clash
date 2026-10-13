package clash

import (
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/ProjectClash/Clash/config"
)

func startedIntentYAML(nodes int) string {
	var b strings.Builder
	b.WriteString("mode: rule\nlog-level: silent\ntun:\n  strict-route: true\n  route-exclude-address: [10.0.0.0/8]\nproxies:\n")
	names := make([]string, 0, nodes)
	for i := 0; i < nodes; i++ {
		name := fmt.Sprintf("node-%03d", i)
		names = append(names, name)
		fmt.Fprintf(&b, "  - {name: %s, type: socks5, server: 10.0.%d.%d, port: 1080, username: user, password: secret%03d, udp: true}\n", name, i/250, i%250+1, i)
	}
	b.WriteString("proxy-groups:\n  - name: PROXY\n    type: select\n    proxies: [")
	b.WriteString(strings.Join(names, ", "))
	b.WriteString("]\nrules:\n  - MATCH,DIRECT\n")
	return b.String()
}

func freshIntent(t *testing.T, text string) string {
	t.Helper()
	raw, err := config.UnmarshalRawConfig([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	data, err := platformConfigIntentFromRaw(raw)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func allocatedBy(f func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

func startForIntent(t *testing.T, text string) {
	t.Helper()
	if err := Setup(testOptions(t)); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	service, err := NewService(newRecordingPlatform())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	t.Cleanup(func() { _ = service.Close() })
	if err := service.Start(text); err != nil {
		t.Fatalf("Start: %v", err)
	}
}

func TestTheIntentAskedAfterStartDoesNotDecodeTheProfileAgain(t *testing.T) {
	text := startedIntentYAML(213)
	startForIntent(t, text)
	want := freshIntent(t, text)
	fresh := allocatedBy(func() { _ = freshIntent(t, text) })

	var got string
	asked := allocatedBy(func() {
		box, err := PlatformConfigIntentJSON(text)
		if err != nil {
			t.Fatal(err)
		}
		got = box.Value
	})
	t.Logf("intent after Start: %d B allocated; a decode of the profile allocates %d B", asked, fresh)
	if got != want {
		t.Fatalf("intent after Start = %s, want %s", got, want)
	}
	if asked > 32<<10 {
		t.Fatalf("the intent after Start allocated %d B (a decode allocates %d B): it decoded the profile again", asked, fresh)
	}

	again, err := PlatformConfigIntentJSON(text)
	if err != nil {
		t.Fatal(err)
	}
	if again.Value != want {
		t.Fatalf("intent asked again = %s, want %s", again.Value, want)
	}
}

func TestTheRememberedIntentAnswersOnlyTheStartedTextAndStack(t *testing.T) {
	old := currentIPStackSettings()
	defer setIPStackSettings(old)
	text := startedIntentYAML(4)
	startForIntent(t, text)

	other := strings.Replace(text, "strict-route: true", "strict-route: false", 1)
	box, err := PlatformConfigIntentJSON(other)
	if err != nil {
		t.Fatal(err)
	}
	if box.Value != freshIntent(t, other) {
		t.Fatalf("another text was answered with the started one's intent: %s", box.Value)
	}

	changed, _ := parseIPStackSettings("ipv4-only", "disabled")
	if changed == currentIPStackSettings() {
		changed, _ = parseIPStackSettings("prefer-ipv6", "enabled")
	}
	setIPStackSettings(changed)
	box, err = PlatformConfigIntentJSON(text)
	if err != nil {
		t.Fatal(err)
	}
	if box.Value != freshIntent(t, text) {
		t.Fatalf("a changed IP stack was answered with the started one's intent: %s", box.Value)
	}
}
