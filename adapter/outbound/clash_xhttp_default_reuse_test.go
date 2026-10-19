package outbound

import (
	"testing"

	"github.com/ProjectClash/Clash/transport/xhttp"
)

func xhttpTestNode(t *testing.T, reuse *XHTTPReuseSettings, download *XHTTPDownloadSettings) (upload, down *xhttp.ReuseConfig) {
	t.Helper()
	node, err := NewVless(VlessOption{
		Name:    "xhttp",
		Server:  "127.0.0.1",
		Port:    443,
		UUID:    "b831381d-6324-4d53-ad4f-8cda48b30811",
		TLS:     true,
		Network: "xhttp",
		XHTTPOpts: XHTTPOptions{
			Path:             "/x",
			Mode:             "stream-up",
			ReuseSettings:    reuse,
			DownloadSettings: download,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = node.Close() })
	return node.xhttpClient.ReuseConfigs()
}

func withXHTTPDefaultReuse(t *testing.T, settings *XHTTPReuseSettings) {
	t.Helper()
	previous := xhttpDefaultReuse.Load()
	SetXHTTPDefaultReuse(settings)
	t.Cleanup(func() { SetXHTTPDefaultReuse(previous) })
}

func wantReuse(t *testing.T, what string, got *xhttp.ReuseConfig, want ...string) {
	t.Helper()
	if got == nil {
		t.Fatalf("%s: no reuse, want %q", what, want)
	}
	if runs := []string{got.MaxConcurrency, got.MaxConnections, got.HMaxRequestTimes, got.HMaxReusableSecs}; got.CMaxReuseTimes != "" ||
		runs[0] != want[0] || runs[1] != want[1] || runs[2] != want[2] || runs[3] != want[3] {
		t.Fatalf("%s: runs %q, want %q", what, runs, want)
	}
}

func TestAnXHTTPNodeWithoutReuseSettingsGetsTheTunnelDefault(t *testing.T) {
	withXHTTPDefaultReuse(t, XHTTPTunnelReuse())
	upload, _ := xhttpTestNode(t, nil, nil)
	wantReuse(t, "upload", upload, "", "3", "600-900", "1800-3000")

	server := "127.0.0.2"
	upload, download := xhttpTestNode(t, nil, &XHTTPDownloadSettings{Server: &server})
	wantReuse(t, "upload beside download-settings", upload, "", "3", "600-900", "1800-3000")
	wantReuse(t, "download", download, "", "3", "600-900", "1800-3000")
}

func TestAnXHTTPNodesOwnReuseSettingsRunAsWritten(t *testing.T) {
	withXHTTPDefaultReuse(t, XHTTPTunnelReuse())
	written := &XHTTPReuseSettings{MaxConcurrency: "1", HMaxRequestTimes: "1", HMaxReusableSecs: "60"}
	upload, _ := xhttpTestNode(t, written, nil)
	wantReuse(t, "written upload", upload, "1", "", "1", "60")

	server := "127.0.0.2"
	ownDownload := &XHTTPReuseSettings{MaxConcurrency: "2", HMaxRequestTimes: "3", HMaxReusableSecs: "4"}
	upload, download := xhttpTestNode(t, written, &XHTTPDownloadSettings{Server: &server, ReuseSettings: ownDownload})
	wantReuse(t, "written upload", upload, "1", "", "1", "60")
	wantReuse(t, "written download", download, "2", "", "3", "4")
}

func TestWithoutTheTunnelDefaultAnXHTTPNodeDoesNotReuse(t *testing.T) {
	withXHTTPDefaultReuse(t, nil)
	if upload, download := xhttpTestNode(t, nil, nil); upload != nil || download != nil {
		t.Fatalf("no default set, yet the node reuses: %+v %+v", upload, download)
	}
}

func TestOnlyAReusingXHTTPNodeIsANetworkResetter(t *testing.T) {
	build := func(network string) *Vless {
		t.Helper()
		node, err := NewVless(VlessOption{
			Name: "x", Server: "127.0.0.1", Port: 443, UUID: "b831381d-6324-4d53-ad4f-8cda48b30811",
			TLS: true, Network: network, XHTTPOpts: XHTTPOptions{Path: "/"},
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = node.Close() })
		return node
	}
	withXHTTPDefaultReuse(t, XHTTPTunnelReuse())
	if _, ok := AsNetworkResetter(build("xhttp")); !ok {
		t.Error("an XHTTP node with pooled connections is no network resetter")
	}
	if _, ok := AsNetworkResetter(build("ws")); ok {
		t.Error("a VLESS node over ws keeps no sessions, yet is a network resetter")
	}
	withXHTTPDefaultReuse(t, nil)
	if _, ok := AsNetworkResetter(build("xhttp")); ok {
		t.Error("an XHTTP node that opens a connection per stream keeps no sessions, yet is a network resetter")
	}
}
