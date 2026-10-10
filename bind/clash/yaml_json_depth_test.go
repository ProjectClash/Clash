package clash

import (
	"strings"
	"testing"
)

func nestedJSONArray(depth int) string {
	return `{"rules":` + strings.Repeat("[", depth) + strings.Repeat("]", depth) + "}"
}

func TestJSONToYamlRefusesRunawayNesting(t *testing.T) {
	_, err := JSONToYaml(nestedJSONArray(200_000))
	if err == nil {
		t.Fatal("a document nested 200000 levels deep was accepted; the stack, not the input limit, is what stops it today")
	}
	if !strings.Contains(err.Error(), "nested") {
		t.Fatalf("the refusal does not say what was wrong: %v", err)
	}
}

func TestJSONToYamlRefusesRunawayObjectNesting(t *testing.T) {
	var builder strings.Builder
	const depth = 200_000
	for i := 0; i < depth; i++ {
		builder.WriteString(`{"a":`)
	}
	builder.WriteString("1")
	builder.WriteString(strings.Repeat("}", depth))

	if _, err := JSONToYaml(builder.String()); err == nil {
		t.Fatal("an object nested 200000 levels deep was accepted")
	}
}

func TestJSONToYamlAcceptsOrdinaryNesting(t *testing.T) {
	if _, err := JSONToYaml(nestedJSONArray(64)); err != nil {
		t.Fatalf("64 levels is ordinary and must be accepted: %v", err)
	}
	realistic := `{"proxies":[{"name":"a","type":"ss","server":"1.2.3.4","port":443,` +
		`"cipher":"aes-128-gcm","password":"x","plugin-opts":{"mode":"websocket","headers":{"Host":"e.com"}}}],` +
		`"rules":["MATCH,DIRECT"]}`
	if _, err := JSONToYaml(realistic); err != nil {
		t.Fatalf("a realistic profile must convert: %v", err)
	}
}
