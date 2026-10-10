package clash

import (
	"os"
	"testing"

	"github.com/sirupsen/logrus"
)

const groupYAML = `
mode: rule
log-level: info
dns:
  enable: true
  nameserver:
    - 8.8.8.8
proxies:
  - {name: a, type: socks5, server: 127.0.0.1, port: 1080}
  - {name: b, type: socks5, server: 127.0.0.1, port: 1081}
proxy-groups:
  - name: pick
    type: select
    proxies: [a, b]
  - name: auto
    type: url-test
    url: "https://www.gstatic.com/generate_204"
    interval: 300
    proxies: [a, b]
rules:
  - MATCH,pick
`

func TestControlActions(t *testing.T) {
	t.Cleanup(func() { logrus.SetOutput(os.Stdout) })
	if err := Setup(testOptions(t)); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	svc, err := NewService(newRecordingPlatform())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	if err := svc.Start(groupYAML); err != nil {
		t.Fatalf("Start: %v", err)
	}

	if err := SelectProxy("pick", "b"); err != nil {
		t.Fatalf("SelectProxy: %v", err)
	}
	if err := SelectProxy("pick", "nope"); err == nil {
		t.Fatal("selecting a non-member should fail")
	}
	if err := SelectProxy("a", "b"); err == nil {
		t.Fatal("selecting on a non-group should fail")
	}
	if err := SelectProxy("ghost", "b"); err == nil {
		t.Fatal("unknown group should fail")
	}

	if err := UnfixProxy("pick"); err == nil {
		t.Fatal("unfixing a selector should fail like the kernel route does")
	}
	if err := UnfixProxy("auto"); err != nil {
		t.Fatalf("UnfixProxy: %v", err)
	}
	if err := UnfixProxy("auto"); err != nil {
		t.Fatalf("UnfixProxy twice: %v", err)
	}
	if err := UnfixProxy("ghost"); err == nil {
		t.Fatal("unknown group should fail")
	}
	if err := UnfixProxy("a"); err == nil {
		t.Fatal("a plain node should fail")
	}

	if d := URLTest("ghost", ""); d != -1 {
		t.Fatalf("URLTest(unknown) = %d, want -1", d)
	}

	if CloseConnection("does-not-exist") {
		t.Fatal("CloseConnection on unknown id should return false")
	}
	CloseAllConnections()
}
