package clash

import (
	"encoding/json"
	"testing"
)

func TestReadProxyPayloadBuildsNothing(t *testing.T) {
	payload := []byte("proxies:\n" +
		"  - {name: good, type: ss, server: 192.0.2.1, port: 8388, cipher: aes-128-gcm, password: p}\n" +
		"  - {name: refused, type: ss, server: 192.0.2.2, port: 8388, cipher: no-such-cipher, password: p}\n")
	decode := func(box *StringBox) (proxies []map[string]any, skipped []map[string]any) {
		var report struct {
			Proxies []map[string]any `json:"proxies"`
			Skipped []map[string]any `json:"skipped"`
		}
		if err := json.Unmarshal([]byte(box.Value), &report); err != nil {
			t.Fatal(err)
		}
		return report.Proxies, report.Skipped
	}

	inspected, err := InspectProxyPayloadForIOS(payload, "nodeBundle")
	if err != nil {
		t.Fatal(err)
	}
	importProxies, importSkipped := decode(inspected)
	if len(importProxies) != 1 || len(importSkipped) != 1 || importSkipped[0]["code"] != "coreRejected" {
		t.Fatalf("import must build and refuse the bad node: proxies=%v skipped=%v", importProxies, importSkipped)
	}

	read, err := ReadProxyPayloadForIOS(payload, "nodeBundle")
	if err != nil {
		t.Fatal(err)
	}
	readProxies, readSkipped := decode(read)
	if len(readProxies) != 2 || len(readSkipped) != 0 {
		t.Fatalf("a read builds nothing, so nothing is refused: proxies=%v skipped=%v", readProxies, readSkipped)
	}
	good, _ := json.Marshal(importProxies[0])
	same, _ := json.Marshal(readProxies[0])
	if string(good) != string(same) {
		t.Fatalf("a node both accept must read the same:\n import %s\n read   %s", good, same)
	}
}
