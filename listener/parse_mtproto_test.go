package listener

import (
	"strings"
	"testing"

	IN "github.com/ProjectClash/Clash/listener/inbound"
)

func TestParseListenerMTProto(t *testing.T) {
	const secret = "0123456789abcdef0123456789abcdef"
	l, err := ParseListener(map[string]any{
		"name":   "mtproto-in",
		"type":   "mtproto",
		"listen": "127.0.0.1",
		"port":   5753,
		"secret": "dd" + secret,
		"ipv6":   true,
		"dc-config-url": "https://example.com/mtproto-dc-config.json",
	})
	if err != nil {
		t.Fatal(err)
	}
	option, ok := l.Config().(*IN.MTProtoOption)
	if !ok {
		t.Fatalf("Config() is %T", l.Config())
	}
	if option.Secret != "dd"+secret || !option.IPv6 || option.Listen != "127.0.0.1" || option.Port != "5753" {
		t.Fatalf("decoded %+v", option)
	}

	_, err = ParseListener(map[string]any{
		"name":   "mtproto-in",
		"type":   "mtproto",
		"port":   5753,
		"secret": "ee" + secret + "7777772e676f6f676c652e636f6d",
	})
	if err == nil || !strings.Contains(err.Error(), "fake-TLS") {
		t.Fatalf("an ee secret parsed: %v", err)
	}
}
