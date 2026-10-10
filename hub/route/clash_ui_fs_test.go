package route

import (
	"bytes"
	"io"
	"net"
	nethttp "net/http"
	"os"
	"path/filepath"
	"testing"

	http "github.com/metacubex/http"
)

func serveUI(t *testing.T, dir string) string {
	t.Helper()
	fs := http.StripPrefix("/ui", http.FileServer(clashUserspaceFileSystem{http.Dir(dir)}))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: fs}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	return "http://" + listener.Addr().String()
}


func writeUIFixture(t *testing.T, size int) (string, []byte) {
	t.Helper()
	dir := t.TempDir()
	content := bytes.Repeat([]byte("x"), size)
	copy(content, "HEAD")
	copy(content[size-4:], "TAIL")
	if err := os.WriteFile(filepath.Join(dir, "entry.css"), content, 0o644); err != nil {
		t.Fatal(err)
	}
	return dir, content
}

func TestUIFilesAreNeverBareOSFiles(t *testing.T) {
	dir, _ := writeUIFixture(t, 600)

	file, err := clashUserspaceFileSystem{http.Dir(dir)}.Open("/entry.css")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	if _, bare := file.(interface{ Fd() uintptr }); bare {
		t.Fatal("the served file still exposes an fd the sendfile upgrade can take")
	}
	if _, bare := file.(*os.File); bare {
		t.Fatal("the served file is a bare *os.File; net will upgrade its copy to sendfile")
	}
}

func TestUserspaceFilePassesReadSeekThrough(t *testing.T) {
	dir, content := writeUIFixture(t, 600)

	file, err := clashUserspaceFileSystem{http.Dir(dir)}.Open("/entry.css")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	sniff := make([]byte, 512)
	if _, err := io.ReadFull(file, sniff); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		t.Fatalf("the rewind ServeContent does after sniffing failed: %v", err)
	}
	full, err := io.ReadAll(file)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(full, content) {
		t.Fatalf("second read after rewind returned %d bytes, want %d", len(full), len(content))
	}
}

func TestUIHandlerServesAWholeFilePastTheSniffBoundary(t *testing.T) {
	dir, content := writeUIFixture(t, 5106)

	base := serveUI(t, dir)

	response, err := nethttp.Get(base + "/ui/entry.css")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("reading past the sniff boundary failed: %v", err)
	}
	if !bytes.Equal(body, content) {
		t.Fatalf("served %d bytes, want %d — the exact on-device truncation was 512", len(body), len(content))
	}
}

func TestUserspaceFileListsDirectories(t *testing.T) {
	dir, _ := writeUIFixture(t, 600)

	base := serveUI(t, dir)

	response, err := nethttp.Get(base + "/ui/")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(body, []byte("entry.css")) {
		t.Fatalf("directory listing lost its entries: %s", body)
	}
}
