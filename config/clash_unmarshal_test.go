package config

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/ProjectClash/Clash/component/age"

	"go.yaml.in/yaml/v3"
)

var clashUnmarshalDocuments = map[string]string{
	"inline merge in a node":  "proxies:\n  - {<<: {type: socks5, port: 1}, name: a, server: 10.0.0.1}\n",
	"anchored node":           "proxies:\n  - &a {name: a, type: socks5, server: 10.0.0.1, port: 1080}\nproxy-groups:\n  - {name: G, type: select, proxies: [a], x: *a}\n",
	"alias inside a node":     "x: &v [h2, http/1.1]\nproxies:\n  - {name: a, type: trojan, server: 10.0.0.1, port: 443, alpn: *v}\n",
	"null node":               "proxies:\n  - ~\n",
	"proxies twice":           "proxies:\n  - {name: a}\nproxies:\n  - {name: b}\n",
	"bad node after the list": "proxies:\n  - {name: a, type: socks5}\nmode: [rule]\n",
	"empty":                   "",
	"comment":                 "# nothing\n",
	"ordinary":                "mode: rule\nunified-delay: true\nproxies:\n  - {name: a, type: socks5, server: 10.0.0.1, port: 1080}\n  - name: b\n    type: http\n    server: 10.0.0.2\n    port: 80\nproxy-groups:\n  - {name: G, type: select, proxies: [a, b]}\nrules:\n  - MATCH,G\n",
	"merged":                  "base: &b\n  mode: global\n  tun: {stack: system}\n<<: *b\nx: &n {type: socks5, server: 10.0.0.1, port: 1080}\nproxies:\n  - {<<: *n, name: a}\n",
	"aliased list":            "x: &l\n  - {name: a, type: socks5, server: 10.0.0.1, port: 1080}\nproxies: *l\n",
	"syntax":                  "proxies:\n  - {name: a\nrules: [\n",
	"type error":              "mixed-port: lots\n",
	"duplicate key":           "mode: rule\nmode: global\n",
	"odd key":                 "x-odd:\n  ? [a, b]\n  : c\nmode: rule\n",
	"two documents":           "mode: rule\n---\nmode: global\n",
	"not a mapping":           "- a\n- b\n",
	"alias loop":              "a: &a [*a]\n",
	"unknown anchor":          "proxies: *nowhere\n",
}

func upstreamUnmarshalRawConfig(buf []byte) (*RawConfig, error) {
	rawCfg := DefaultRawConfig()
	buf, err := age.DecryptBytes(buf)
	if err != nil {
		return nil, fmt.Errorf("decrypt config error: %w", err)
	}
	if err := yaml.Unmarshal(buf, rawCfg); err != nil {
		return nil, err
	}
	return rawCfg, nil
}

func TestClashUnmarshalRawConfigIsUnmarshalRawConfig(t *testing.T) {
	for name, text := range clashUnmarshalDocuments {
		t.Run(name, func(t *testing.T) {
			want, wantErr := upstreamUnmarshalRawConfig([]byte(text))
			if upstream, upstreamErr := UnmarshalRawConfig([]byte(text)); fmt.Sprint(upstreamErr) != fmt.Sprint(wantErr) || !reflect.DeepEqual(upstream, want) {
				t.Fatalf("UnmarshalRawConfig: %v, upstream's %v", upstreamErr, wantErr)
			}
			reads := 0
			got, gotErr := ClashUnmarshalRawConfig([]byte(text), func(decode func(any) error) {
				reads++
				for _, shape := range []func() any{
					func() any { return &map[string]any{} },
					func() any {
						return &struct {
							Mode *string `yaml:"mode"`
						}{}
					},
					func() any { return &[]any{} },
					func() any { return DefaultRawConfig() },
				} {
					fromDecode, fromText := shape(), shape()
					decodeErr := decode(fromDecode)
					textErr := yaml.Unmarshal([]byte(text), fromText)
					if fmt.Sprint(decodeErr) != fmt.Sprint(textErr) {
						t.Fatalf("decode into %T: error %v, yaml.Unmarshal's %v", fromDecode, decodeErr, textErr)
					}
					if !reflect.DeepEqual(fromDecode, fromText) {
						t.Fatalf("decode into %T: %+v, yaml.Unmarshal's %+v", fromDecode, fromDecode, fromText)
					}
				}
			})
			if fmt.Sprint(gotErr) != fmt.Sprint(wantErr) {
				t.Fatalf("error %v, UnmarshalRawConfig's %v", gotErr, wantErr)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("RawConfig differs from UnmarshalRawConfig's")
			}
			if reads > 1 {
				t.Fatalf("read ran %d times", reads)
			}
		})
	}
}

func TestClashUnmarshalRawConfigDoesNotReadArmorForTheCaller(t *testing.T) {
	secret, public, err := age.GenX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	age.SetGlobalSecretKeys(secret)
	defer age.SetGlobalSecretKeys()
	armored, err := age.EncryptBytes([]byte("mode: global\n"), public)
	if err != nil {
		t.Fatal(err)
	}
	read := false
	raw, err := ClashUnmarshalRawConfig(armored, func(func(any) error) { read = true })
	if err != nil {
		t.Fatal(err)
	}
	if read {
		t.Fatal("read was handed the decrypted document of an armored text")
	}
	if raw.Mode.String() != "global" {
		t.Fatalf("mode %s, want global", raw.Mode)
	}
}
