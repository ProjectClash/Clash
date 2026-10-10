//go:build no_easytier

package outbound

import (
	"context"
	"encoding/json"
	"testing"

	C "github.com/ProjectClash/Clash/constant"
)

func TestNoEasyTierBuildStandsTheNodeUpAsARejectPlaceholder(t *testing.T) {
	node, err := NewEasyTier(EasyTierOption{
		Name:          "office-mesh",
		NetworkName:   "office",
		NetworkSecret: "secret",
		Peers:         []string{"tcp://203.0.113.10:11010"},
	})
	if err != nil {
		t.Fatalf("a no_easytier build must accept the node, got %v", err)
	}
	if node.Name() != "office-mesh" {
		t.Fatalf("placeholder name = %q, want the node's own name", node.Name())
	}
	if node.Type() != C.Reject {
		t.Fatalf("placeholder type = %v, want %v", node.Type(), C.Reject)
	}
	conn, err := node.DialContext(context.Background(), &C.Metadata{Host: "example.com", DstPort: 443})
	if err != nil {
		t.Fatalf("a reject placeholder answers the dial the way REJECT does, got %v", err)
	}
	defer conn.Close()
	buffer := make([]byte, 1)
	if n, readErr := conn.Read(buffer); n != 0 || readErr == nil {
		t.Fatalf("a reject placeholder must refuse the connection: read %d bytes, err %v", n, readErr)
	}
}

func TestNoEasyTierPlaceholderNamesItsDeclaredTypeInJSON(t *testing.T) {
	node, err := NewEasyTier(EasyTierOption{Name: "office-mesh", NetworkName: "office"})
	if err != nil {
		t.Fatal(err)
	}
	data, err := node.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	var mapping map[string]any
	if err := json.Unmarshal(data, &mapping); err != nil {
		t.Fatalf("placeholder JSON does not parse: %v", err)
	}
	if mapping["type"] != "Reject" || mapping["placeholderType"] != "easytier" {
		t.Fatalf("placeholder JSON = %s, want type Reject and placeholderType easytier", data)
	}
	if _, ok := mapping["id"]; !ok {
		t.Fatalf("placeholder JSON lost the Base fields: %s", data)
	}
}
