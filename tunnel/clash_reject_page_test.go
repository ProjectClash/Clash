package tunnel

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	N "github.com/ProjectClash/Clash/common/net"
	C "github.com/ProjectClash/Clash/constant"
	icontext "github.com/ProjectClash/Clash/context"
)

func TestARefusedHTTPRequestIsAnsweredWithThePage(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	conn := N.NewBufferedConn(server)
	go func() { _, _ = client.Write([]byte("GET /ad.js HTTP/1.1\r\nHost: ads.example\r\n\r\n")) }()
	done := make(chan bool, 1)
	go func() {
		var peek sync.Mutex
		done <- answerRejectWithPage(conn, &peek, &C.Metadata{NetWork: C.TCP, DstPort: 80})
		_ = server.Close()
	}()
	response, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusForbidden || !strings.Contains(string(body), "This page was blocked on this device.") ||
		response.ContentLength != int64(len(body)) {
		t.Fatalf("answered %d %q (length %d)", response.StatusCode, body, response.ContentLength)
	}
	if !<-done {
		t.Fatal("the page was written but not reported")
	}
}

func TestARefusedFlowThatIsNotHTTPGetsNoPage(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() { _, _ = client.Write([]byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0, 0, 0, 0}) }()
	var peek sync.Mutex
	if answerRejectWithPage(N.NewBufferedConn(server), &peek, &C.Metadata{NetWork: C.TCP, DstPort: 443}) {
		t.Fatal("a ClientHello was answered with the page")
	}
}

func TestTheRejectPageSpeaksTheLanguageTheBrowserAsksFor(t *testing.T) {
	for header, want := range map[string]string{
		"":                           "en",
		"en-US,en;q=0.9":             "en",
		"zh-CN,zh;q=0.9":             "zh-Hans",
		"zh-Hans-CN":                 "zh-Hans",
		"zh-TW":                      "zh-Hant",
		"zh-HK,zh;q=0.9,en;q=0.8":    "zh-Hant",
		"zh-Hant":                    "zh-Hant",
		"zh-MO":                      "zh-Hant",
		"zh":                         "zh-Hans",
		"ja-JP,zh-TW;q=0.8,en;q=0.5": "zh-Hant",
		"ja,fr":                      "en",
		"en;q=0.5,zh-CN;q=0.8":       "zh-Hans",
		"zh-CN;q=0,en":               "en",
		"ZH-tw":                      "zh-Hant",
	} {
		if got := rejectPageLanguage(header); got != want {
			t.Errorf("Accept-Language %q: %s, want %s", header, got, want)
		}
	}
}

func TestARefusedRequestIsAnsweredInItsLanguage(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	conn := N.NewBufferedConn(server)
	go func() {
		_, _ = client.Write([]byte("GET / HTTP/1.1\r\nHost: ads.example\r\nAccept-Language: zh-TW,zh;q=0.9\r\n\r\n"))
	}()
	go func() {
		var peek sync.Mutex
		answerRejectWithPage(conn, &peek, &C.Metadata{NetWork: C.TCP, DstPort: 80})
		_ = server.Close()
	}()
	response, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	if response.Header.Get("Content-Language") != "zh-Hant" || !strings.Contains(string(body), "這個網頁在這台裝置上被攔截了。") {
		t.Fatalf("answered %s: %q", response.Header.Get("Content-Language"), body)
	}
}

type pageVerdictConn struct {
	*verdictConn
	mu      sync.Mutex
	written []byte
}

func (c *pageVerdictConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.written = append(c.written, b...)
	return len(b), nil
}

func TestTheTunnelAnswersARefusedPlainRequestWithThePage(t *testing.T) {
	reject := &dialProxy{doorProxy: doorProxy{name: "REJECT", typ: C.Reject}, dial: func() (C.Conn, error) {
		return nothingConn{N.NewExtendedConn(eofConn{})}, nil
	}}
	for _, on := range []bool{true, false} {
		withVerdictTunnel(t, "REJECT", reject)
		prevRouting := loadVersion().routing
		UpdateClashRouting(C.ClashRouting{RejectPage: on})
		inner := newVerdictConn(true)
		inner.firstBytes = []byte("GET / HTTP/1.1\r\nHost: ads.example\r\nAccept-Language: zh-CN\r\n\r\n")
		conn := &pageVerdictConn{verdictConn: inner}
		metadata := tunFlowTo("192.0.2.1")
		metadata.DstPort = 80
		handleTCPConn(icontext.NewConnContext(conn, metadata))
		UpdateClashRouting(prevRouting)
		conn.mu.Lock()
		written := string(conn.written)
		conn.mu.Unlock()
		err, told := inner.verdict(t)
		if on {
			if !strings.Contains(written, "HTTP/1.1 403") || !strings.Contains(written, "这个网页在这台设备上被拦截了。") {
				t.Fatalf("with the page on, the app read %q", written)
			}
		} else if !told || !errors.Is(err, errRejectedByRule) || written != "" {
			t.Fatalf("with the page off: told=%v err=%v written=%q, want the reset", told, err, written)
		}
	}
}

func TestTheRejectPageReadsWhatTheClientStillSends(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	conn := N.NewBufferedConn(server)
	done := make(chan time.Duration, 1)
	go func() {
		_, _ = client.Write([]byte("POST /up HTTP/1.1\r\nHost: ads.example\r\nContent-Length: 10240\r\n\r\n"))
	}()
	go func() {
		var peek sync.Mutex
		start := time.Now()
		answerRejectWithPage(conn, &peek, &C.Metadata{NetWork: C.TCP, DstPort: 80})
		done <- time.Since(start)
		_ = server.Close()
	}()
	if _, err := http.ReadResponse(bufio.NewReader(client), nil); err != nil {
		t.Fatal(err)
	}
	wrote := make(chan error, 1)
	go func() { _, err := client.Write(make([]byte, 10240)); wrote <- err }()
	select {
	case err := <-wrote:
		if err != nil {
			t.Fatalf("the body could not be sent: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("nothing read the request body after the page")
	}
	if took := <-done; took > rejectPageHeadersWait+rejectPageLinger+time.Second {
		t.Fatalf("the refused request held the connection %s", took)
	}
}
