package clash

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"
)

func TestASnellV6NodeReachesSurgesServer(t *testing.T) {
	server := os.Getenv("CLASH_SNELL_SERVER")
	if server == "" {
		t.Skip("CLASH_SNELL_SERVER names no snell-server")
	}
	echo := tcpEcho(t, nil)
	banner := []byte("220 ready\r\n")
	speaksFirst := tcpEcho(t, banner)
	udpTarget := udpEcho(t)
	for _, mode := range []string{"default", "unshaped", "unsafe-raw"} {
		for _, reuse := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/reuse=%v", mode, reuse), func(t *testing.T) {
				port := startSurgeSnellServer(t, server, mode)
				withSnellV6Tunnel(t, snellV6Node(t, port, mode, reuse))
				local := forwardAddress(t, forwardThroughV6(t, echo), "tcp")
				for i := 0; i < 3; i++ {
					conn := dialThrough(t, local)
					roundTrip(t, conn, 256<<10)
					_ = conn.Close()
				}

				conn := dialThrough(t, forwardAddress(t, forwardThroughV6(t, speaksFirst), "tcp"))
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				got := make([]byte, len(banner))
				if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, banner) {
					t.Fatalf("the banner: %q (%v)", got, err)
				}

				packets, err := net.Dial("udp", forwardAddress(t, forwardThroughV6(t, udpTarget), "udp"))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = packets.Close() })
				_ = packets.SetDeadline(time.Now().Add(5 * time.Second))
				for _, size := range []int{1, 1200} {
					sent := bytes.Repeat([]byte{byte(size)}, size)
					if _, err := packets.Write(sent); err != nil {
						t.Fatal(err)
					}
					back := make([]byte, 2048)
					n, err := packets.Read(back)
					if err != nil || !bytes.Equal(back[:n], sent) {
						t.Fatalf("a %d-byte datagram came back as %d bytes (%v)", size, n, err)
					}
				}
			})
		}
	}

	t.Run("a mode the server does not run", func(t *testing.T) {
		port := startSurgeSnellServer(t, server, "default")
		withSnellV6Tunnel(t, snellV6Node(t, port, "unshaped", false))
		conn := dialThrough(t, forwardAddress(t, forwardThroughV6(t, echo), "tcp"))
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		_, _ = conn.Write([]byte("hello"))
		if n, err := io.ReadFull(conn, make([]byte, 5)); err == nil {
			t.Fatalf("an unshaped node carried %d bytes through a default server", n)
		}
	})
}

func startSurgeSnellServer(t *testing.T, server, mode string) int {
	t.Helper()
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	_ = probe.Close()
	conf := filepath.Join(t.TempDir(), "snell-server.conf")
	text := fmt.Sprintf("[snell-server]\nlisten = 127.0.0.1:%d\npsk = %s\nmode = %s\n", port, snellV6TestPSK, mode)
	if err := os.WriteFile(conf, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	output := &serverOutput{}
	process := exec.Command(server, "-c", conf)
	process.Stdout, process.Stderr = output, output
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = process.Process.Kill()
		_ = process.Wait()
		if t.Failed() {
			t.Logf("snell-server said:\n%s", output.String())
		}
	})
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	for deadline := time.Now().Add(5 * time.Second); ; {
		if conn, err := net.DialTimeout("tcp", address, 200*time.Millisecond); err == nil {
			_ = conn.Close()
			return port
		}
		if time.Now().After(deadline) {
			t.Fatalf("snell-server did not listen on %s:\n%s", address, output.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

type serverOutput struct {
	mu   sync.Mutex
	text bytes.Buffer
}

func (o *serverOutput) Write(p []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.text.Write(p)
}

func (o *serverOutput) String() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.text.String()
}
