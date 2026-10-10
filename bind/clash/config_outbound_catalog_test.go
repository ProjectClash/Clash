//go:build with_gvisor

package clash

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ProjectClash/Clash/adapter"
	"github.com/ProjectClash/Clash/config"
	"github.com/metacubex/ssh"
)

func TestOfficialOutboundCatalogParses(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "docs", "config.yaml"))
	if err != nil {
		t.Fatalf("read official config catalog: %v", err)
	}
	raw, err := config.UnmarshalRawConfig(data)
	if err != nil {
		t.Fatalf("unmarshal official config catalog: %v", err)
	}

	type fixture struct {
		typeName string
		ordinal  int
		mapping  map[string]any
	}
	fixtures := make([]fixture, 0, len(raw.Proxy)+1)
	seenByType := map[string]int{}
	for _, original := range raw.Proxy {
		mapping := cloneMapping(original)
		typeName, _ := mapping["type"].(string)
		if typeName == "" {
			continue
		}
		normalizeOfficialCatalogPlaceholders(typeName, mapping)
		if typeName == "ssh" {
			if value, _ := mapping["private-key"].(string); value != "" {
				passphrase, _ := mapping["private-key-passphrase"].(string)
				key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
				block, err := ssh.MarshalPrivateKey(key, "schema-fixture")
				if passphrase != "" {
					block, err = ssh.MarshalPrivateKeyWithPassphrase(key, "schema-fixture", []byte(passphrase))
				}
				if err != nil {
					t.Fatalf("create SSH schema fixture: %v", err)
				}
				mapping["private-key"] = string(pem.EncodeToMemory(block))
			}
		}
		if typeName == "openvpn" {
			mapping["ca"] = "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----"
			mapping["cert"] = ""
			mapping["key"] = ""
			mapping["username"] = "fixture"
			mapping["password"] = "fixture"
		}
		ordinal := seenByType[typeName]
		seenByType[typeName]++
		fixtures = append(fixtures, fixture{typeName: typeName, ordinal: ordinal, mapping: mapping})
	}
	fixtures = append(fixtures, fixture{typeName: "reject", mapping: map[string]any{"name": "reject-probe", "type": "reject"}})
	seenByType["reject"]++

	expectedTypes := []string{
		"ss", "ssr", "socks5", "http", "vmess", "vless", "snell", "trojan",
		"hysteria", "hysteria2", "wireguard", "tuic", "shadowquic", "gost-relay", "direct",
		"dns", "reject", "rematch", "ssh", "mieru", "anytls", "sudoku", "masque",
		"trusttunnel", "openvpn", "tailscale", "zerotier", "easytier",
	}
	for _, typeName := range expectedTypes {
		if seenByType[typeName] == 0 {
			t.Errorf("official config catalog has no %q outbound fixture", typeName)
		}
	}
	if len(seenByType) != len(expectedTypes) {
		t.Fatalf("official config catalog types = %d, want %d; parser inventory must classify every type", len(seenByType), len(expectedTypes))
	}

	for _, item := range fixtures {
		item := item
		t.Run(fmt.Sprintf("%s-%02d", item.typeName, item.ordinal), func(t *testing.T) {
			proxy, err := adapter.ParseProxy(item.mapping)
			if err != nil {
				t.Fatalf("parse official %s fixture: %v", item.typeName, err)
			}
			if err := proxy.Close(); err != nil {
				t.Fatalf("close %s fixture: %v", item.typeName, err)
			}
		})
	}
}

func normalizeOfficialCatalogPlaceholders(typeName string, mapping map[string]any) {
	if typeName == "ss" {
		for _, key := range []string{"server", "password"} {
			if choices, ok := mapping[key].([]any); ok && len(choices) > 0 {
				mapping[key] = choices[0]
			}
		}
		if pluginOptions, ok := mapping["plugin-opts"].(map[string]any); ok {
			pluginOptions = cloneMapping(pluginOptions)
			if choices, ok := pluginOptions["password"].([]any); ok && len(choices) > 0 {
				pluginOptions["password"] = choices[0]
			}
			mapping["plugin-opts"] = pluginOptions
		}
	}
	if typeName != "vless" {
		return
	}

	if value, ok := mapping["encryption"].(string); ok && strings.Contains(value, "(") {
		mapping["encryption"] = "none"
	}
	reality, ok := mapping["reality-opts"].(map[string]any)
	if !ok || reality["public-key"] != "xxx" {
		return
	}
	reality = cloneMapping(reality)
	key := make([]byte, 32)
	for i := range key {
		key[i] = 1
	}
	reality["public-key"] = base64.RawURLEncoding.EncodeToString(key)
	reality["short-id"] = "0123456789abcdef"
	mapping["reality-opts"] = reality
}

func cloneMapping(source map[string]any) map[string]any {
	result := make(map[string]any, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}
