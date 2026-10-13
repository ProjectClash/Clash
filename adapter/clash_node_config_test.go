package adapter

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/ProjectClash/Clash/common/convert"
)

func TestANodeConfigurationComesBackWithItsTypes(t *testing.T) {
	cases := []map[string]any{
		{"name": "n", "type": "ss", "port": 443, "udp": true, "password": "p"},
		{
			"name": "every type", "type": "vmess",
			"nil": nil, "false": false, "true": true, "empty": "",
			"int": -7, "int8": int8(-8), "int16": int16(-16), "int32": int32(-32), "int64": int64(-1 << 40),
			"uint": uint(7), "uint8": uint8(8), "uint16": uint16(16), "uint32": uint32(32), "uint64": uint64(1 << 63),
			"float32": float32(1.5), "float64": 2.25,
			"list":     []any{1, "two", []any{3.0}, map[string]any{"four": 4}},
			"strings":  []string{"h3", "not a word", ""},
			"map":      map[string]any{"path": "/", "headers": map[string]any{"Host": "example.net"}},
			"strmap":   map[string]string{"Host": "example.net", "": ""},
			"anymap":   map[any]any{1: "one", "two": 2, true: nil},
			"maplist":  []map[string]any{{"a": 1}, {}},
			"uuid":     "0123abcd-4567-89ef-0123-456789abcdef",
			"UUID":     "0123ABCE-4567-89EF-0123-456789ABCDEF",
			"nearuuid": "0123abcd-4567-89ef-0123-456789abcdeg",
			"emptymap": map[string]any{}, "emptylist": []any{},
		},
	}
	for _, mapping := range cases {
		config, ok := encodeNodeConfig(mapping)
		if !ok {
			t.Fatalf("%v: not encoded", mapping["name"])
		}
		back, err := decodeNodeConfig(config)
		if err != nil {
			t.Fatalf("%v: %v", mapping["name"], err)
		}
		if !reflect.DeepEqual(back, mapping) {
			t.Fatalf("%v: came back as\n%#v\nwant\n%#v", mapping["name"], back, mapping)
		}
	}
}

func TestEveryConvertedShareLinkIsEncoded(t *testing.T) {
	links := "ss://YWVzLTEyOC1nY206cGFzcw@example.net:8388#ss\n" +
		"trojan://pass@example.net:443?sni=example.net&type=ws&path=%2Fws#trojan\n" +
		"vless://0123abcd-4567-89ef-0123-456789abcdef@example.net:443?security=reality&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=01&fp=chrome&type=grpc&serviceName=g#vless\n" +
		"hysteria2://pass@example.net:443?sni=example.net&obfs=salamander&obfs-password=x#hy2\n" +
		"tuic://0123abcd-4567-89ef-0123-456789abcdef:pass@example.net:443?alpn=h3&congestion_control=bbr#tuic\n"
	nodes, err := convert.ConvertsV2Ray([]byte(links))
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 5 {
		t.Fatalf("converted %d nodes", len(nodes))
	}
	for _, mapping := range nodes {
		config, ok := encodeNodeConfig(mapping)
		if !ok {
			t.Fatalf("%v: a converted node holds a type the encoding does not keep: %#v", mapping["name"], mapping)
		}
		back, err := decodeNodeConfig(config)
		if err != nil || !reflect.DeepEqual(back, mapping) {
			t.Fatalf("%v: came back as %#v (%v)", mapping["name"], back, err)
		}
	}
}

func TestAnUnknownValueTypeIsNotEncoded(t *testing.T) {
	type named int
	for _, value := range []any{named(1), struct{}{}, []int{1}, map[int]int{}, (map[string]any)(nil), &struct{}{}} {
		if _, ok := encodeNodeConfig(map[string]any{"name": "n", "x": value}); ok {
			t.Errorf("%T encoded", value)
		}
	}
}

func TestADamagedConfigurationIsAnError(t *testing.T) {
	config, ok := encodeNodeConfig(clashMixedNodes(t, 5)[1])
	if !ok {
		t.Fatal("not encoded")
	}
	for cut := 0; cut < len(config); cut++ {
		if _, err := decodeNodeConfig(config[:cut]); err == nil {
			t.Fatalf("a configuration cut at %d of %d decoded", cut, len(config))
		}
	}
	for _, bad := range []string{"\xff", "\x14\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01", "\x04\xff\x7f", "\x13\x01\x03"} {
		if _, err := decodeNodeConfig(bad); err == nil {
			t.Fatalf("%q decoded", bad)
		}
	}
	if _, err := decodeNodeConfig(config + "\x00"); err == nil {
		t.Fatal("trailing bytes decoded")
	}
}

func TestTheWordTableHasNoDuplicates(t *testing.T) {
	seen := map[string]bool{}
	for _, word := range nodeConfigWords {
		if seen[word] {
			t.Errorf("%q twice", word)
		}
		seen[word] = true
	}
}

func TestTheEncodingIsSmallerThanJSON(t *testing.T) {
	nodes := clashMixedNodes(t, 1000)
	var encoded, asJSON int
	for _, mapping := range nodes {
		config, ok := encodeNodeConfig(mapping)
		if !ok {
			t.Fatalf("%v: not encoded", mapping["name"])
		}
		encoded += len(config)
		raw, err := json.Marshal(mapping)
		if err != nil {
			t.Fatal(err)
		}
		asJSON += len(raw)
	}
	t.Logf("mixed corpus: %d B a node encoded, %d B as JSON", encoded/len(nodes), asJSON/len(nodes))
	if encoded >= asJSON {
		t.Fatalf("encoded %d B against JSON's %d B", encoded, asJSON)
	}
}

func TestEqualMappingsEncodeEqually(t *testing.T) {
	first, _ := encodeNodeConfig(clashMixedNode(t, 1))
	for i := 0; i < 50; i++ {
		again, _ := encodeNodeConfig(clashMixedNode(t, 1))
		if again != first {
			t.Fatal("one mapping encoded two ways")
		}
	}
}

func TestNodeConfigWordsAreOnlyAppended(t *testing.T) {
	const pinned, pinnedSHA256 = 207, "6381dc05fe780d430b36643457a485540dac2c17ad546f9d2068cbd7a6bb9f06"
	if len(nodeConfigWords) < pinned {
		t.Fatalf("%d words, fewer than the %d node libraries on disk index", len(nodeConfigWords), pinned)
	}
	sum := sha256.Sum256([]byte(strings.Join(nodeConfigWords[:pinned], "\x00")))
	if got := hex.EncodeToString(sum[:]); got != pinnedSHA256 {
		t.Fatalf("the first %d words changed (%s): append new words, never insert, remove or reorder", pinned, got)
	}
	if cfgMapList != 23 {
		t.Fatalf("the tags were renumbered: cfgMapList is %d", cfgMapList)
	}
}
