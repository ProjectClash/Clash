package yaml

import (
	"reflect"
	"testing"
)

func TestClashParseDocumentKeepsNoNodesOfTheSequence(t *testing.T) {
	in := []byte("mode: rule\nproxies:\n  - {name: a, type: ss, port: 1}\n  - {name: b, type: trojan, port: 2}\nproxy-groups:\n  - {name: g, proxies: [a, b]}\n")
	document, err := ClashParseDocument(in, ClashSequence{Key: "proxies", Item: reflect.TypeOf(map[string]interface{}{})})
	if err != nil {
		t.Fatal(err)
	}
	root := document.Content[0]
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == "proxies" && len(root.Content[i+1].Content) != 0 {
			t.Fatalf("the sequence kept %d nodes", len(root.Content[i+1].Content))
		}
		if root.Content[i].Value == "proxy-groups" && len(root.Content[i+1].Content) != 1 {
			t.Fatal("the rest of the document lost its nodes")
		}
	}
	var got, want map[string]interface{}
	if err := document.Decode(&got); err != nil {
		t.Fatal(err)
	}
	if err := Unmarshal(in, &want); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("decoded %v, Unmarshal %v", got, want)
	}
}
