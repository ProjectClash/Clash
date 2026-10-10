package xhttp

import (
	"context"
	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
	"github.com/metacubex/http/httptrace"
	"io"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"
)

type queryCaptureTransport func(*http.Request) (*http.Response, error)

func (f queryCaptureTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestConfiguredQueryOnWire(t *testing.T) {
	for _, mode := range []string{"stream-one", "stream-up", "packet-up"} {
		t.Run(mode, func(t *testing.T) {
			requests := make(chan *http.Request, 4)
			maker := func() http.RoundTripper {
				return queryCaptureTransport(func(r *http.Request) (*http.Response, error) {
					requests <- r
					if trace := httptrace.ContextClientTrace(r.Context()); trace != nil && trace.GotConn != nil {
						a, b := net.Pipe()
						trace.GotConn(httptrace.GotConnInfo{Conn: a})
						a.Close()
						b.Close()
					}
					return &http.Response{StatusCode: 200, Status: "200 OK", Body: http.NoBody, Header: make(http.Header)}, nil
				})
			}
			cfg := &Config{Host: "example.com", Path: "/?ed=2560&token=a%2Fb&duplicate=one&duplicate=two", Mode: mode}
			if mode != "stream-one" {
				cfg.DownloadConfig = &Config{Host: "download.example.com", Path: "/down?ed=1280&token=c%2Fd&duplicate=one&duplicate=two"}
			}
			c, err := NewClient(cfg, maker, maker, false)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			conn, err := c.Dial(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			count := 1
			if mode == "stream-up" {
				count = 2
			}
			if mode == "packet-up" {
				w := &PacketUpWriter{ctx: ctx, cfg: cfg, transport: maker(), sessionID: "session"}
				if _, err := w.write([]byte("data")); err != nil {
					t.Fatal(err)
				}
				count = 2
			}
			for n := 0; n < count; n++ {
				select {
				case r := <-requests:
					if strings.Contains(r.URL.Path, "?") {
						t.Errorf("query encoded in path: %q", r.URL.Path)
					}
					ed, token := "2560", "a/b"
					if r.Host == "download.example.com" {
						ed, token = "1280", "c/d"
					}
					if r.URL.Query().Get("ed") != ed || r.URL.Query().Get("token") != token || len(r.URL.Query()["duplicate"]) != 2 {
						t.Errorf("configured query lost: path=%q query=%q", r.URL.Path, r.URL.RawQuery)
					}
				case <-ctx.Done():
					t.Fatal("missing HTTP request")
				}
			}
		})
	}
}
func TestServerAcceptsNativeQueryPath(t *testing.T) {
	cfg := Config{Path: "/?ed=2560", Mode: "stream-one"}
	handler, err := NewServerHandler(ServerOption{Config: cfg, ConnHandler: func(c net.Conn) { c.Close() }})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "https://example.com/?ed=2560", io.NopCloser(http.NoBody))
	if err := cfg.FillStreamRequest(req, ""); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Result().StatusCode != 200 {
		t.Fatalf("native query request rejected: HTTP %d", w.Result().StatusCode)
	}
}

func TestConfiguredPathWithoutQueryKeepsNormalization(t *testing.T) {
	for _, tc := range []struct{ path, placement, want string }{{"", "", "/"}, {"/", "", "/"}, {"root", "", "/root/"}, {"/root", "", "/root/"}, {"/root/", "", "/root/"}, {"root", "header", "/root"}, {"/root", "query", "/root"}, {"", "query", "/"}} {
		t.Run(tc.path+"/"+tc.placement, func(t *testing.T) {
			c := Config{Path: tc.path, SessionPlacement: tc.placement, SeqPlacement: tc.placement}
			if got := c.NormalizedPath(); got != tc.want {
				t.Fatalf("path=%q want%q", got, tc.want)
			}
			if c.NormalizedQuery() != "" {
				t.Fatal("query invented")
			}
		})
	}
}
func TestConfiguredQueryCoexistsWithMetadataAndPadding(t *testing.T) {
	c := Config{Host: "example.com", Path: "/stream?keep=a%2Fb&duplicate=one&duplicate=two&session=old&seq=old&padding=old&nested=a?b", SessionPlacement: PlacementQuery, SessionKey: "session", SeqPlacement: PlacementQuery, SeqKey: "seq", XPaddingObfsMode: true, XPaddingPlacement: PlacementQuery, XPaddingKey: "padding", XPaddingMethod: "repeat-x", XPaddingBytes: "16-16"}
	u := url.URL{Scheme: "https", Host: c.Host, Path: c.NormalizedPath(), RawQuery: c.NormalizedQuery()}
	r, err := http.NewRequest(http.MethodPost, u.String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.FillPacketRequest(r, "current-session", "4", []byte("body")); err != nil {
		t.Fatal(err)
	}
	q := r.URL.Query()
	if q.Get("keep") != "a/b" || len(q["duplicate"]) != 2 || q.Get("nested") != "a?b" {
		t.Fatalf("configured query lost: %v", q)
	}
	if q.Get("session") != "current-session" || q.Get("seq") != "4" || q.Get("padding") == "old" || len(q["session"]) != 1 || len(q["padding"]) != 1 {
		t.Fatalf("existing metadata Set behavior changed: %v", q)
	}
	if r.URL.Path != "/stream" {
		t.Fatalf("query metadata changed path: %q", r.URL.Path)
	}
}
