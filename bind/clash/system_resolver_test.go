package clash

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestReadResolvConfKeepsUsableNameserversInFileOrder(t *testing.T) {
	const text = `#
# macOS Notice
#
domain example.lan
search example.lan corp.example
nameserver 192.168.1.1
nameserver 2001:4860:4860::8888
nameserver fe80::1%en0
nameserver 198.18.0.2
nameserver fdfe:dcba:9876::2
nameserver ::
nameserver 224.0.0.251
nameserver not-an-address
nameserver
nameserver 1.1.1.1 trailing words
options ndots:1
`
	got := readResolvConf(strings.NewReader(text))
	want := []string{"192.168.1.1", "2001:4860:4860::8888", "1.1.1.1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("readResolvConf = %v, want %v (link-local, the tunnel's own ranges, unspecified and multicast go; everything else stays in file order)", got, want)
	}
}

func TestSystemResolverLinesReadsTheFileMihomoReadsAndIsEmptyWithoutIt(t *testing.T) {
	stubPlatformResolvers(t, nil, nil)
	stubRoutes(t, 11, nil, map[string]int{"119.29.29.29": 11, "223.5.5.5": 11}, nil)
	withResolvConf(t, "nameserver 119.29.29.29\nnameserver 223.5.5.5\n")
	if got, want := SystemResolverLines(), "119.29.29.29\n223.5.5.5"; got != want {
		t.Fatalf("SystemResolverLines = %q, want %q", got, want)
	}
	resolvConfPath = filepath.Join(t.TempDir(), "missing")
	if got := SystemResolverLines(); got != "" {
		t.Fatalf("a missing file must read as no resolvers, got %q", got)
	}
}

func TestSystemResolverLinesReadsUpstreamsFile(t *testing.T) {
	if resolvConfPath != "/etc/resolv.conf" {
		t.Fatalf("resolvConfPath = %q, want /etc/resolv.conf", resolvConfPath)
	}
}

func withResolvConf(t *testing.T, text string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "resolv.conf")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := resolvConfPath
	resolvConfPath = path
	t.Cleanup(func() { resolvConfPath = previous })
}
