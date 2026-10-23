package clash

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func finalizeAtPathForTest(t *testing.T, path, dir string) string {
	t.Helper()
	resources, _ := json.Marshal(map[string]any{"runtimeProfile": RuntimeProfileIOSPacketTunnel, "ruleIndexDirectory": dir, "nodeLibraryDirectory": dir})
	options, _ := json.Marshal(map[string]any{"targetProfile": RuntimeProfileIOSPacketTunnel, "plan": true, "intent": true})
	box, err := FinalizeForIOSWithOptionsAtPath(path, string(resources), string(options))
	if err != nil {
		t.Fatal(err)
	}
	return box.Value
}

func TestAPlanAndItsFinalizeParseTheFileOnce(t *testing.T) {
	t.Cleanup(dropKeptParse)
	dir := t.TempDir()
	path := filepath.Join(t.TempDir(), "config.yaml")
	text := ruleIndexTestDocument(3000)
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	alone := finalizeAtPathForTest(t, path, dir)

	count := func(steps func()) int64 {
		before := publishParses.Load()
		steps()
		return publishParses.Load() - before
	}
	plan := func() {
		if _, err := PlanResourcesForProfileAtPath(path, RuntimeProfileIOSPacketTunnel); err != nil {
			t.Fatal(err)
		}
	}
	var published string
	if n := count(func() { plan(); published = finalizeAtPathForTest(t, path, dir) }); n != 1 {
		t.Fatalf("a plan and its finalize parsed the file %d times", n)
	}
	if published != alone {
		t.Fatalf("the finalize of the plan's parse published\n%.400s\nalone\n%.400s", published, alone)
	}
	if n := count(func() { plan(); FreeMemory(); finalizeAtPathForTest(t, path, dir) }); n != 2 {
		t.Fatalf("with a FreeMemory between, %d parses", n)
	}
	changed := strings.Replace(text, "  - MATCH,Proxy\n", "  - DOMAIN,changed.example,DIRECT\n  - MATCH,Proxy\n", 1)
	var again string
	if n := count(func() {
		plan()
		if err := os.WriteFile(path+".new", []byte(changed), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(path+".new", path); err != nil {
			t.Fatal(err)
		}
		again = finalizeAtPathForTest(t, path, dir)
	}); n != 2 {
		t.Fatalf("with the file written again between, %d parses", n)
	}
	if again == published {
		t.Fatal("the finalize published the plan's parse of the file before it was written again")
	}
	if n := count(func() {
		plan()
		resources, _ := json.Marshal(map[string]any{"runtimeProfile": RuntimeProfileIOSPacketTunnel, "nodeLibraryDirectory": dir})
		if _, err := FinalizeForIOSWithOptionsAtPath(path, string(resources), "{}"); err != nil {
			t.Fatal(err)
		}
	}); n != 2 {
		t.Fatalf("a finalize of another resource map: %d parses", n)
	}
	other := filepath.Join(t.TempDir(), "page.yaml")
	if err := os.WriteFile(other, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := PlanResourcesForProfileAtPath(other, RuntimeProfileIOSPacketTunnel); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(other)
	deadline := time.Now().Add(5 * time.Second)
	for {
		keptParse.Lock()
		kept := keptParse.parsed != nil
		keptParse.Unlock()
		if !kept {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("a parse outlived its file")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if n := count(func() {
		var answer struct{ Text string }
		if err := json.Unmarshal([]byte(again), &answer); err != nil || !strings.Contains(answer.Text, "x-clash-rule-index") {
			t.Fatalf("no published text: %v", err)
		}
		republished := filepath.Join(t.TempDir(), "published.yaml")
		if err := os.WriteFile(republished, []byte(answer.Text), 0o600); err != nil {
			t.Fatal(err)
		}
		finalizeAtPathForTest(t, republished, dir)
	}); n != 1 {
		t.Fatalf("a published text published again parsed %d times", n)
	}
	saved := keptParseLifetime
	keptParseLifetime = 20 * time.Millisecond
	t.Cleanup(func() { keptParseLifetime = saved })
	plan()
	time.Sleep(200 * time.Millisecond)
	keptParse.Lock()
	kept := keptParse.parsed != nil
	keptParse.Unlock()
	if kept {
		t.Fatal("a parse outlived its lifetime")
	}
}
