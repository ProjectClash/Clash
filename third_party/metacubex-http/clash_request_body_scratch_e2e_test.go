package http_test

import (
	"crypto/sha256"
	"fmt"
	"io"
	"testing"
	"time"

	. "github.com/metacubex/http"
)

func TestAStreamingRequestBodyArrivesWholeWithItsScratchTakenOnDemand(t *testing.T) {
	previousMax := SetHTTP2StreamingBodyScratchMax(64 << 10)
	previousOnDemand := HTTP2StreamingBodyScratchOnDemand()
	defer func() {
		SetHTTP2StreamingBodyScratchMax(previousMax)
		SetHTTP2StreamingBodyScratchOnDemand(previousOnDemand)
	}()
	var chunks [][]byte
	want, total := sha256.New(), 0
	for i, size := range []int{1, 2, 3, 5, 65535, 65536, 65537, 1, 200000, 7, 1 << 20, 1} {
		chunk := make([]byte, size)
		for j := range chunk {
			chunk[j] = byte(i*31 + j)
		}
		chunks = append(chunks, chunk)
		want.Write(chunk)
		total += size
	}
	wanted := fmt.Sprintf("%d %x", total, want.Sum(nil))
	for _, onDemand := range []bool{true, false} {
		SetHTTP2StreamingBodyScratchOnDemand(onDemand)
		cst := newClientServerTest(t, http2Mode, HandlerFunc(func(w ResponseWriter, r *Request) {
			sum := sha256.New()
			n, err := io.Copy(sum, r.Body)
			if err != nil {
				t.Errorf("the server's read of the body: %v", err)
			}
			fmt.Fprintf(w, "%d %x", n, sum.Sum(nil))
		}))
		reader, writer := io.Pipe()
		go func() {
			for _, chunk := range chunks {
				if _, err := writer.Write(chunk); err != nil {
					return
				}
			}
			_ = writer.Close()
		}()
		req, err := NewRequest("POST", cst.ts.URL, reader)
		if err != nil {
			t.Fatal(err)
		}
		res, err := cst.c.Do(req)
		if err != nil {
			t.Fatalf("on demand %v: %v", onDemand, err)
		}
		got, err := io.ReadAll(res.Body)
		_ = res.Body.Close()
		if err != nil || string(got) != wanted {
			t.Fatalf("on demand %v: the server received %q (%v), want %q", onDemand, got, err, wanted)
		}
		if res.ProtoMajor != 2 {
			t.Fatalf("on demand %v: the request went over HTTP/%d", onDemand, res.ProtoMajor)
		}
		cst.close()
	}
}

func TestAOneByteWriteIsSentWithoutWaitingForTheNextWithTheScratchOnDemand(t *testing.T) {
	previousMax := SetHTTP2StreamingBodyScratchMax(64 << 10)
	previousOnDemand := SetHTTP2StreamingBodyScratchOnDemand(true)
	defer func() {
		SetHTTP2StreamingBodyScratchMax(previousMax)
		SetHTTP2StreamingBodyScratchOnDemand(previousOnDemand)
	}()
	arrived := make(chan string, 16)
	cst := newClientServerTest(t, http2Mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		buf := make([]byte, 16)
		for {
			n, err := r.Body.Read(buf)
			if n > 0 {
				arrived <- string(buf[:n])
			}
			if err != nil {
				return
			}
		}
	}))
	defer cst.close()
	reader, writer := io.Pipe()
	defer writer.Close()
	req, err := NewRequest("POST", cst.ts.URL, reader)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		res, err := cst.c.Do(req)
		if err == nil {
			_ = res.Body.Close()
		}
		done <- err
	}()
	for _, write := range []string{"a", "b", "cd", "e"} {
		if _, err := writer.Write([]byte(write)); err != nil {
			t.Fatal(err)
		}
		select {
		case got := <-arrived:
			if got != write {
				t.Fatalf("the server read %q, want the write %q", got, write)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("the write %q had not reached the server after 2 s with no write behind it", write)
		}
	}
	_ = writer.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
