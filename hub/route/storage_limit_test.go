package route

import (
	"bytes"
	"io"
	"testing"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
)

type countingReader struct {
	read int
	data io.Reader
}

func (r *countingReader) Read(p []byte) (int, error) {
	n, err := r.data.Read(p)
	r.read += n
	return n, err
}

func TestStorageRefusesAnOversizedBodyBeforeReadingIt(t *testing.T) {
	body := &countingReader{data: bytes.NewReader(bytes.Repeat([]byte("a"), 8<<20))}
	request := httptest.NewRequest(http.MethodPut, "/key", body)
	recorder := httptest.NewRecorder()
	storageRouter().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status %d, want 413", recorder.Code)
	}
	if body.read > storageMaxBodyBytes+64<<10 {
		t.Fatalf("read %d bytes of an 8 MiB body before refusing; the limit must stop the read", body.read)
	}
}
