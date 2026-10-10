package clash

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCompileRuleProviderTurnsDomainTextIntoAnArtifactTheCoreReads(t *testing.T) {
	dir := compileStagingHome(t)
	source := filepath.Join(dir, "domains.txt")
	if err := os.WriteFile(source, []byte("example.com\n+.example.org\nfull:exact.example.net\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "domains.mrs")

	result, err := CompileRuleProvider(source, "domain", "text", out)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if !result.Compiled {
		t.Fatalf("domain text must compile, got reason %q", result.Reason)
	}
	if result.Rules != 3 {
		t.Fatalf("carried %d rules, want 3", result.Rules)
	}
	info, err := os.Stat(out)
	if err != nil || info.Size() == 0 {
		t.Fatalf("artifact missing or empty: %v", err)
	}
	artifact, readErr := os.ReadFile(out)
	if readErr != nil {
		t.Fatal(readErr)
	}
	count, err := InspectProviderForIOS("rule", "domain", "mrs", artifact)
	if err != nil {
		t.Fatalf("core refused its own artifact: %v", err)
	}
	if count != 3 {
		t.Fatalf("artifact holds %d rules, want 3", count)
	}
}

func TestCompileRuleProviderDegradesAClassicalListThatIsOnlyDomains(t *testing.T) {
	dir := compileStagingHome(t)
	source := filepath.Join(dir, "classical.list")
	body := "DOMAIN,example.com\nDOMAIN-SUFFIX,example.org\n# a comment\n\n"
	if err := os.WriteFile(source, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "classical.mrs")

	result, err := CompileRuleProvider(source, "classical", "text", out)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if !result.Compiled {
		t.Fatalf("a classical list of only domains can compile, got %q", result.Reason)
	}
	if result.Behavior != "domain" {
		t.Fatalf("compiled as %q, want the degraded domain behavior", result.Behavior)
	}
	if result.Rules != 2 {
		t.Fatalf("carried %d rules, want 2", result.Rules)
	}
}

func TestCompileRuleProviderRefusesAClassicalListItCannotCarry(t *testing.T) {
	for name, body := range map[string]string{
		"keyword": "DOMAIN,example.com\nDOMAIN-KEYWORD,ads\n",
		"ipcidr":  "DOMAIN,example.com\nIP-CIDR,10.0.0.0/8\n",
		"logic":   "AND,((DOMAIN,example.com),(NETWORK,tcp))\n",
		"process": "PROCESS-NAME,curl\n",
	} {
		t.Run(name, func(t *testing.T) {
			dir := compileStagingHome(t)
			source := filepath.Join(dir, "classical.list")
			if err := os.WriteFile(source, []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
			out := filepath.Join(dir, "classical.mrs")

			result, err := CompileRuleProvider(source, "classical", "text", out)
			if err != nil {
				t.Fatalf("a list that cannot compile is not an error: %v", err)
			}
			if result.Compiled {
				t.Fatalf("%s must stay classical", name)
			}
			if result.Reason == "" {
				t.Fatal("a refusal has to say what it could not carry")
			}
			if _, err := os.Stat(out); err == nil {
				t.Fatal("a refused compile must leave no artifact behind")
			}
		})
	}
}

func TestCompileRuleProviderNamesTheRuleItCouldNotCarry(t *testing.T) {
	dir := compileStagingHome(t)
	source := filepath.Join(dir, "classical.list")
	if err := os.WriteFile(source, []byte("DOMAIN,example.com\nDOMAIN-KEYWORD,ads\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := CompileRuleProvider(source, "classical", "text", filepath.Join(dir, "out.mrs"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result.Reason, "DOMAIN-KEYWORD") {
		t.Fatalf("reason %q does not name the rule kind that stopped it", result.Reason)
	}
}

func TestCompileRuleProviderLeavesAlreadyCompiledSetsAlone(t *testing.T) {
	dir := compileStagingHome(t)
	source := filepath.Join(dir, "already.mrs")
	if err := os.WriteFile(source, []byte("not really mrs"), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := CompileRuleProvider(source, "domain", "mrs", filepath.Join(dir, "out.mrs"))
	if err != nil {
		t.Fatal(err)
	}
	if result.Compiled {
		t.Fatal("an mrs set is the artifact; compiling it again is work for nothing")
	}
}
