package tun

import (
	"context"
	"errors"
	"net"
	"testing"
)

type statsRequest struct {
	acceptErr error
	rejected  int
}

func (r *statsRequest) accept(ctx context.Context) (net.Conn, error) {
	if r.acceptErr != nil {
		return nil, r.acceptErr
	}
	client, server := net.Pipe()
	_ = client.Close()
	return server, nil
}

func (r *statsRequest) reject() error {
	r.rejected++
	return nil
}

func (r *statsRequest) done() <-chan struct{} { return nil }

func TestDeferredHandshakeSnapshotCountsEveryOutcome(t *testing.T) {
	resetDeferredHandshakeStatsForTest()
	if got := DeferredHandshakeSnapshot(); got != (DeferredHandshakeReport{Pending: deferredHandshakesPending()}) {
		t.Fatalf("fresh snapshot = %+v", got)
	}

	for i := 0; i < deferredHandshakeBudget; i++ {
		if !acquireDeferredHandshake() {
			t.Fatalf("permit %d refused inside the budget", i)
		}
	}
	if acquireDeferredHandshake() {
		t.Fatal("a permit past the budget was granted")
	}
	got := DeferredHandshakeSnapshot()
	if got.Deferred != deferredHandshakeBudget || got.BudgetSpent != 1 || got.Pending != deferredHandshakeBudget {
		t.Fatalf("after spending the budget: %+v", got)
	}
	for i := 0; i < deferredHandshakeBudget; i++ {
		releaseDeferredHandshake()
	}

	completed := newDeferredConn(context.Background(), &statsRequest{}, nil, nil, nil)
	if err := completed.HandshakeSuccess(); err != nil {
		t.Fatalf("HandshakeSuccess: %v", err)
	}
	_ = completed.Close()

	notCompleted := newDeferredConn(context.Background(), &statsRequest{acceptErr: errors.New("no final ACK")}, nil, nil, nil)
	if err := notCompleted.HandshakeSuccess(); err == nil {
		t.Fatal("an accept that failed must be reported")
	}

	refused := &statsRequest{}
	if err := newDeferredConn(context.Background(), refused, nil, nil, nil).HandshakeFailure(errors.New("dial failed")); err != nil {
		t.Fatalf("HandshakeFailure: %v", err)
	}
	closed := &statsRequest{}
	_ = newDeferredConn(context.Background(), closed, nil, nil, nil).Close()
	if refused.rejected != 1 || closed.rejected != 1 {
		t.Fatalf("each refused flow spends its request once: %d, %d", refused.rejected, closed.rejected)
	}

	got = DeferredHandshakeSnapshot()
	want := DeferredHandshakeReport{Deferred: deferredHandshakeBudget, BudgetSpent: 1, Completed: 1, NotCompleted: 1, Refused: 2, Pending: 0}
	if got != want {
		t.Fatalf("snapshot = %+v, want %+v", got, want)
	}
}
