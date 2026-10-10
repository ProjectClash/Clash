package clash

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestTheShareLinkLedgerCoversWhatUpstreamSupports(t *testing.T) {
	probes := []string{
		"udp", "tls", "sni", "alpn", "fingerprint", "skip-cert-verify", "tfo",
		"mptcp", "ip-version", "udp-over-tcp", "client-fingerprint", "servername",
		"flow", "packet-encoding",
	}
	synonyms := map[string][]string{
		"clientfingerprint": {"fp", "fingerprint"},
		"servername":        {"sni", "peer", "tlsservername"},
		"skipcertverify":    {"insecure", "allowinsecure"},
	}
	upstreamName := map[string]string{"ss": "shadowsocks", "ssr": "shadowsocksr"}

	normalise := func(key string) string {
		return strings.NewReplacer("-", "", "_", "").Replace(strings.ToLower(key))
	}

	supported := map[string]map[string]bool{}
	optionType := regexp.MustCompile(`type\s+(\w*Option)\s+struct\s*\{`)
	tag := regexp.MustCompile(`proxy:"([^",]+)`)
	entries, err := os.ReadDir(filepath.Join("..", "..", "adapter", "outbound"))
	if err != nil {
		t.Fatalf("cannot read upstream's outbounds: %v", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		body, err := os.ReadFile(filepath.Join("..", "..", "adapter", "outbound", entry.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", entry.Name(), err)
		}
		text := string(body)
		for _, match := range optionType.FindAllStringSubmatchIndex(text, -1) {
			name := strings.ToLower(strings.TrimSuffix(text[match[2]:match[3]], "Option"))
			end := strings.Index(text[match[1]:], "\n}")
			if end < 0 {
				continue
			}
			fields := supported[name]
			if fields == nil {
				fields = map[string]bool{}
				supported[name] = fields
			}
			for _, t2 := range tag.FindAllStringSubmatch(text[match[1]:match[1]+end], -1) {
				fields[normalise(t2[1])] = true
			}
		}
	}
	if len(supported) == 0 {
		t.Fatal("read no outbound option structs; the derivation is wrong, not the ledger")
	}

	checked, gaps := 0, 0
	for scheme, registered := range proxyImportQueryFieldLedger.get() {
		fields := supported[scheme]
		if name, ok := upstreamName[scheme]; ok {
			fields = supported[name]
		}
		if len(fields) == 0 {
			continue
		}
		checked++
		have := map[string]bool{}
		for key := range registered {
			have[normalise(key)] = true
		}
		for _, probe := range probes {
			key := normalise(probe)
			if !fields[key] || have[key] {
				continue
			}
			spelled := false
			for _, synonym := range synonyms[key] {
				if have[normalise(synonym)] {
					spelled = true
					break
				}
			}
			if spelled {
				continue
			}
			gaps++
			t.Errorf("%s: upstream's outbound has %q and the ledger does not register it, so a share "+
				"link carrying it is refused. This is how the user's socks5 security=tls and ss udp=1 "+
				"were rejected -- for fields mihomo supports.", scheme, probe)
		}
	}
	if checked == 0 {
		t.Fatal("no scheme was compared against an upstream outbound; the name mapping is wrong")
	}
	t.Logf("compared %d schemes against upstream's outbound options; %d gap(s)", checked, gaps)
}
