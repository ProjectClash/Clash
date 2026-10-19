package clash

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var libraryChecksum = regexp.MustCompile(`(nodes-[0-9a-f]+\.library\n\s+sha256: )[0-9a-f]+`)

func TestAPublishReadingTheRulesInPlacePublishesWhatHoldingThemDoes(t *testing.T) {
	head := "proxies:\n  - {name: P, type: direct}\nproxy-groups:\n  - {name: G, type: select, proxies: [P, DIRECT]}\n"
	for name, rules := range map[string]string{
		"plain":             "rules:\n  - DOMAIN,a.example,P\n  - DOMAIN-SUFFIX,Example.org,G\n  - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve\n  - MATCH,P\n",
		"quoted":            "rules:\n  - 'DOMAIN,a.example,P'\n  - \"DST-PORT,8443,DIRECT\"\n  - MATCH,P\n",
		"uid":               "rules:\n  - UID,501,P\n  - DOMAIN,a.example,P\n  - AND,((UID,0),(DOMAIN,b.example)),G\n  - MATCH,DIRECT\n",
		"folded":            "rules:\n  - DOMAIN,a.example,\n    P\n  - MATCH,P\n",
		"flow":              "rules: [DOMAIN,a.example,P, 'MATCH,P']\n",
		"comments":          "rules: # head\n  - DOMAIN,a.example,P # tail\n  # between\n  - MATCH,P\n",
		"null":              "rules:\n  - DOMAIN,a.example,P\n  - ~\n  - MATCH,P\n",
		"number":            "rules:\n  - 123\n  - MATCH,P\n",
		"anchored":          "rules: &r\n  - DOMAIN,a.example,P\n  - MATCH,P\nx-copy: *r\n",
		"bad target":        "rules:\n  - DOMAIN,a.example,Nowhere\n  - MATCH,P\n",
		"mapping":           "rules:\n  - {DOMAIN: a.example}\n  - MATCH,P\n",
		"none":              "mode: rule\n",
		"empty":             "rules: []\n",
		"sub-rules":         "sub-rules:\n  s1:\n    - DOMAIN,b.example,P\n    - MATCH,DIRECT\nrules:\n  - SUB-RULE,(NETWORK,tcp),s1\n  - MATCH,P\n",
		"folded indicator":  "rules:\n  - >2-\n    DOMAIN-SUFFIX,\n    a.example,P\n  - MATCH,DIRECT\n",
		"literal indicator": "rules:\n  - |2-\n    DST-PORT,443,P\n  - MATCH,DIRECT\n",
		"literal no target": "rules:\n  - |4\n      DST-PORT,443\n  - MATCH,DIRECT\n",
	} {
		t.Run(name, func(t *testing.T) {
			document := head + rules
			publish := func(inPlace bool) (string, error, map[string][]byte) {
				finalizeReadsRulesInPlace = inPlace
				defer func() { finalizeReadsRulesInPlace = true }()
				dir := t.TempDir()
				resources, _ := json.Marshal(map[string]any{"runtimeProfile": RuntimeProfileIOSPacketTunnel, "ruleIndexDirectory": dir, "nodeLibraryDirectory": dir})
				finalized, err := FinalizeForIOS(document, string(resources))
				files := map[string][]byte{}
				entries, _ := os.ReadDir(dir)
				for _, entry := range entries {
					if strings.HasPrefix(entry.Name(), ruleIndexPrefix) {
						data, _ := os.ReadFile(filepath.Join(dir, entry.Name()))
						files[entry.Name()] = data
					}
				}
				if err != nil {
					return "", err, files
				}
				text := strings.ReplaceAll(finalized.Value, dir, "<dir>")
				return libraryChecksum.ReplaceAllString(text, "${1}<sha256>"), nil, files
			}
			held, heldErr, heldFiles := publish(false)
			inPlace, inPlaceErr, inPlaceFiles := publish(true)
			if (heldErr == nil) != (inPlaceErr == nil) || (heldErr != nil && heldErr.Error() != inPlaceErr.Error()) {
				t.Fatalf("errors: held %v, in place %v", heldErr, inPlaceErr)
			}
			if held != inPlace {
				t.Fatalf("published:\n%s\nin place:\n%s", held, inPlace)
			}
			if len(heldFiles) != len(inPlaceFiles) {
				t.Fatalf("indexes: held %d, in place %d", len(heldFiles), len(inPlaceFiles))
			}
			for file, data := range heldFiles {
				if !bytes.Equal(data, inPlaceFiles[file]) {
					t.Fatalf("index %s differs", file)
				}
			}
		})
	}
}
