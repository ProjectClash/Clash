package inbound_test

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
)


func streamingBodyServer(t *testing.T) (server *httptest.Server, started chan struct{}, arrived chan string) {
	t.Helper()
	started, arrived = make(chan struct{}, 4), make(chan string, 16)
	server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			t.Errorf("the request came over HTTP/%d", r.ProtoMajor)
		}
		started <- struct{}{}
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
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)
	return server, started, arrived
}

func TestAOneByteWriteToAStreamingBodyIsSentWhenItIsWritten(t *testing.T) {
	withStreamingBodyScratchMax(t, 64<<10)
	for _, onDemand := range []bool{true, false} {
		withStreamingBodyScratchOnDemand(t, onDemand)
		server, _, arrived := streamingBodyServer(t)
		reader, writer := io.Pipe()
		t.Cleanup(func() { _ = writer.Close() })
		req, err := http.NewRequest("POST", server.URL, reader)
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() {
			res, err := server.Client().Do(req)
			if err == nil {
				_ = res.Body.Close()
			}
			done <- err
		}()
		for _, write := range []string{"a", "b", "cd", "e"} {
			if _, err := writer.Write([]byte(write)); err != nil {
				t.Fatalf("on demand %v: %v", onDemand, err)
			}
			select {
			case got := <-arrived:
				if got != write {
					t.Fatalf("on demand %v: the server read %q, want the write %q", onDemand, got, write)
				}
			case <-time.After(2 * time.Second):
				_ = writer.Close()
				t.Fatalf("on demand %v: the write %q had not reached the server after 2 s with no write behind it", onDemand, write)
			}
		}
		_ = writer.Close()
		if err := <-done; err != nil {
			t.Fatalf("on demand %v: %v", onDemand, err)
		}
	}
}

func TestARequestCancelledWhileItsStreamingBodyIsSilentLetsGoOfTheBody(t *testing.T) {
	withStreamingBodyScratchMax(t, 64<<10)
	for _, onDemand := range []bool{true, false} {
		for _, wroteFirst := range []bool{false, true} {
			withStreamingBodyScratchOnDemand(t, onDemand)
			server, started, arrived := streamingBodyServer(t)
			reader, writer := io.Pipe()
			t.Cleanup(func() { _ = writer.Close() })
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			req, err := http.NewRequestWithContext(ctx, "POST", server.URL, reader)
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				res, err := server.Client().Do(req)
				if err == nil {
					_ = res.Body.Close()
				}
				done <- err
			}()
			select {
			case <-started:
			case <-time.After(5 * time.Second):
				t.Fatalf("on demand %v: the request did not reach the server", onDemand)
			}
			if wroteFirst {
				if _, err := writer.Write([]byte("k")); err != nil {
					t.Fatal(err)
				}
				select {
				case <-arrived:
				case <-time.After(2 * time.Second):
					t.Fatalf("on demand %v: the write before the cancel did not arrive", onDemand)
				}
			}
			cancel()
			select {
			case err := <-done:
				if err == nil {
					t.Fatalf("on demand %v, a write first %v: a cancelled request ended without an error", onDemand, wroteFirst)
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("on demand %v, a write first %v: the cancelled request did not end", onDemand, wroteFirst)
			}
			refused := make(chan error, 1)
			go func() {
				_, err := writer.Write([]byte("late"))
				refused <- err
			}()
			select {
			case err := <-refused:
				if err == nil {
					t.Fatalf("on demand %v, a write first %v: a write after the cancel was taken", onDemand, wroteFirst)
				}
			case <-time.After(5 * time.Second):
				_ = writer.Close()
				t.Fatalf("on demand %v, a write first %v: the body was not let go of -- a write after the cancel waits", onDemand, wroteFirst)
			}
		}
	}
}

func TestStreamingBodiesSentTogetherArriveWholeEachItsOwn(t *testing.T) {
	withStreamingBodyScratchMax(t, 64<<10)
	withStreamingBodyScratchOnDemand(t, true)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sum := sha256.New()
		n, err := io.Copy(sum, r.Body)
		if err != nil {
			t.Errorf("the server's read of a body: %v", err)
		}
		fmt.Fprintf(w, "%d %x", n, sum.Sum(nil))
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)
	client := server.Client()
	const uploads, writes = 8, 250
	var wg sync.WaitGroup
	for upload := 0; upload < uploads; upload++ {
		wg.Add(1)
		go func(upload int) {
			defer wg.Done()
			reader, writer := io.Pipe()
			sent := make(chan string, 1)
			go func() {
				want, total := sha256.New(), 0
				defer func() { sent <- fmt.Sprintf("%d %x", total, want.Sum(nil)) }()
				for write := 0; write < writes; write++ {
					size := 1 + (write*7919+upload*104729)%40000
					if write%5 == 0 {
						size = 1 + write%3
					}
					chunk := make([]byte, size)
					for i := range chunk {
						chunk[i] = byte(upload*37 + write*11 + i)
					}
					want.Write(chunk)
					total += size
					if _, err := writer.Write(chunk); err != nil {
						_ = writer.CloseWithError(err)
						return
					}
				}
				_ = writer.Close()
			}()
			req, err := http.NewRequest("POST", server.URL, reader)
			if err != nil {
				t.Error(err)
				return
			}
			res, err := client.Do(req)
			if err != nil {
				_ = reader.Close()
				t.Errorf("upload %d: %v", upload, err)
				return
			}
			got, err := io.ReadAll(res.Body)
			_ = res.Body.Close()
			if wanted := <-sent; err != nil || string(got) != wanted {
				t.Errorf("upload %d: the server received %q (%v), want %q", upload, got, err, wanted)
			}
			if res.ProtoMajor != 2 {
				t.Errorf("upload %d went over HTTP/%d", upload, res.ProtoMajor)
			}
		}(upload)
	}
	wg.Wait()
}
