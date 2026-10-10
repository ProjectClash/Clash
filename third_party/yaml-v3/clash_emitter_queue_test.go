package yaml

import (
	"fmt"
	"reflect"
	"testing"
)

func TestTheEmitterQueueHoldsOnlyItsLookAhead(t *testing.T) {
	var document []interface{}
	for i := 0; i < 5000; i++ {
		document = append(document, map[string]interface{}{"name": fmt.Sprintf("node-%d", i), "port": 443, "tags": []string{"a", "b"}})
	}
	e := newEncoder()
	defer e.destroy()
	e.marshalDoc("", reflect.ValueOf(map[string]interface{}{"proxies": document}))
	e.finish()
	if held := cap(e.emitter.events); held > 64 {
		t.Errorf("the emitter's queue grew to %d events for one document", held)
	}
}

func TestTheEmitterWritesTheSameDocumentWithItsQueueStartingOver(t *testing.T) {
	document := map[string]interface{}{
		"proxies": []interface{}{map[string]interface{}{"name": "a", "type": "ss", "server": "192.0.2.1", "port": 443}},
		"rules":   []interface{}{"DOMAIN-SUFFIX,example.invalid,a", "MATCH,DIRECT"},
		"dns":     map[string]interface{}{"enable": true, "nameserver": []interface{}{"223.5.5.5"}},
	}
	out, err := Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	const want = "dns:\n    enable: true\n    nameserver:\n        - 223.5.5.5\nproxies:\n    - name: a\n      port: 443\n      server: 192.0.2.1\n      type: ss\nrules:\n    - DOMAIN-SUFFIX,example.invalid,a\n    - MATCH,DIRECT\n"
	if string(out) != want {
		t.Errorf("marshalled\n%s\nwant\n%s", out, want)
	}
}
