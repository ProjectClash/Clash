package provider

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestAProvidersFileDecodesAsUpstreamDecodesIt(t *testing.T) {
	var long strings.Builder
	long.WriteString("proxies:\n")
	for i := 0; i < 500; i++ {
		fmt.Fprintf(&long, "  - {name: n%d, type: ss, server: 10.0.%d.%d, port: %d, cipher: aes-128-gcm, password: p%d}\n", i, i/250, i%250, 1000+i, i)
	}
	documents := map[string]string{
		"list":           long.String(),
		"whole config":   "mode: rule\n" + long.String() + "proxy-groups:\n  - {name: G, type: select, proxies: [n0, n1]}\nrules:\n  - MATCH,G\n",
		"flow":           "proxies: [{name: a, type: ss}, {name: b, type: http}]\n",
		"empty":          "proxies: []\n",
		"none":           "mode: rule\n",
		"merged node":    "x: &n {type: ss, port: 1}\nproxies:\n  - {<<: *n, name: a}\n",
		"scalar node":    "proxies:\n  - a\n",
		"syntax after":   long.String() + "x: [\n",
		"not yaml":       "c3M6Ly9ZV1Z6TFRFeU9DMW5ZMjA2Y0dGemMzZHZjbVE9QDEwLjAuMC4xOjgzODgjYQ==",
		"share links":    "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ=@10.0.0.1:8388#a\n",
		"twice":          "proxies:\n  - {name: a}\nproxies:\n  - {name: b}\n",
		"bad node":       "proxies:\n  - {name: a, name: b}\n",
		"proxies scalar": "proxies: a\n",
	}
	for name, document := range documents {
		t.Run(name, func(t *testing.T) {
			want, got := &ProxySchema{}, &ProxySchema{}
			wantErr := yaml.Unmarshal([]byte(document), want)
			gotErr := clashUnmarshalProxySchema([]byte(document), got)
			if fmt.Sprint(gotErr) != fmt.Sprint(wantErr) {
				t.Fatalf("error %v, yaml.Unmarshal's %v", gotErr, wantErr)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("schema %#v, yaml.Unmarshal's %#v", got, want)
			}
		})
	}
}
