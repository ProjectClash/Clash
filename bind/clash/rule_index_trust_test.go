package clash

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"
	"testing"

	"github.com/ProjectClash/Clash/config"
	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/hub/executor"
)

func TestAServiceOutsideTheExtensionLeavesIndexesProved(t *testing.T) {
	opts := testOptions(t)
	opts.RuntimeProfile = RuntimeProfileMacOSApplication
	if err := Setup(opts); err != nil {
		t.Fatal(err)
	}
	old := config.ClashRuleIndexesVerified.Swap(false)
	t.Cleanup(func() { config.ClashRuleIndexesVerified.Store(old) })

	compiler := config.NewClashRuleIndexCompiler(func(string) bool { return true }, func(string) bool { return false }, nil)
	for _, line := range []string{"DOMAIN,a.example,DIRECT", "DOMAIN,b.example,REJECT", "MATCH,DIRECT"} {
		if err := compiler.Add(line); err != nil {
			t.Fatal(err)
		}
	}
	var buffer bytes.Buffer
	if _, _, err := compiler.Write(&buffer); err != nil {
		t.Fatal(err)
	}
	data := buffer.Bytes()
	le := binary.LittleEndian
	exact := int(le.Uint32(data[56+8*4:]))
	keys := exact + 12 + 4*int(le.Uint32(data[exact:]))
	a, b := le.Uint32(data[keys+8:]), le.Uint32(data[keys+20:])
	le.PutUint32(data[keys+8:], b)
	le.PutUint32(data[keys+20:], a)
	sum := sha256.Sum256(data[:len(data)-32])
	copy(data[len(data)-32:], sum[:])
	path := t.TempDir() + "/x.index"
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	text := []byte(fmt.Sprintf("x-clash-rule-index: {path: %q, sha256: %x}\n", path, sum))
	if _, err := executor.ParseWithBytes(text); err == nil {
		t.Fatal("an unproved index parsed before NewService")
	}
	service, err := NewService(newRecordingPlatform())
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	cfg, err := executor.ParseWithBytes(text)
	if err == nil {
		cfg.RuleTable.Walk(&C.Metadata{Host: "a.example"}, C.RuleMatchHelper{}, nil, func(_ int, _ C.Rule, target string) bool {
			t.Errorf("an unproved index parsed after NewService outside the extension; a.example went %s", target)
			return true
		})
	}
	if config.ClashRuleIndexesVerified.Load() {
		t.Error("NewService outside the extension marked the process the tunnel's")
	}
}

func TestTheServiceInTheExtensionTrustsTheAppsProof(t *testing.T) {
	if err := Setup(testOptions(t)); err != nil {
		t.Fatal(err)
	}
	old := config.ClashRuleIndexesVerified.Swap(false)
	t.Cleanup(func() { config.ClashRuleIndexesVerified.Store(old) })
	platform := newRecordingPlatform()
	platform.underNetworkExtension = true
	service, err := NewService(platform)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	if !config.ClashRuleIndexesVerified.Load() {
		t.Fatal("the extension's service did not mark the process the tunnel's")
	}
}
