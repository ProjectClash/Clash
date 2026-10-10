package adapter

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
	"testing"
)


func TestClassifyURLTestFailureReadsTypesNotWords(t *testing.T) {
	for _, tc := range []struct {
		name      string
		err       error
		satisfied bool
		status    int
		wantKind  string
		wantErrno string
	}{
		{
			name:      "loopback write refused by a bound socket",
			err:       fmt.Errorf("dns resolve failed: %w", &net.OpError{Op: "write", Err: syscall.EADDRNOTAVAIL}),
			satisfied: true,
			wantKind:  "write",
			wantErrno: "EADDRNOTAVAIL",
		},
		{
			name:      "nothing listening",
			err:       &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED},
			satisfied: true,
			wantKind:  "dial",
			wantErrno: "ECONNREFUSED",
		},
		{
			name:      "probe outlived its deadline",
			err:       fmt.Errorf("get: %w", context.DeadlineExceeded),
			satisfied: true,
			wantKind:  "timeout",
			wantErrno: "",
		},
		{
			name:      "caller hung up",
			err:       fmt.Errorf("get: %w", context.Canceled),
			satisfied: true,
			wantKind:  "canceled",
			wantErrno: "",
		},
		{
			name:      "answered with an unexpected status",
			err:       nil,
			satisfied: false,
			status:    403,
			wantKind:  "status",
			wantErrno: "",
		},
		{
			name:      "something with no type to read",
			err:       errors.New("a sentence and nothing else"),
			satisfied: true,
			wantKind:  "unknown",
			wantErrno: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyURLTestFailure(tc.err, tc.satisfied, tc.status)
			if got == nil {
				t.Fatalf("no failure classified")
			}
			if got.Kind != tc.wantKind {
				t.Errorf("kind = %q, want %q", got.Kind, tc.wantKind)
			}
			if got.Errno != tc.wantErrno {
				t.Errorf("errno = %q, want %q", got.Errno, tc.wantErrno)
			}
		})
	}
}

func TestClassifyURLTestFailureKeepsTheVerbatimSentence(t *testing.T) {
	err := fmt.Errorf("dns resolve failed: %w", &net.OpError{Op: "write", Err: syscall.EADDRNOTAVAIL})
	got := ClassifyURLTestFailure(err, true, 0)
	if got.Message != err.Error() {
		t.Fatalf("message = %q, want the error verbatim %q", got.Message, err.Error())
	}
}

func TestClassifyURLTestFailureIsNilOnSuccess(t *testing.T) {
	if got := ClassifyURLTestFailure(nil, true, 204); got != nil {
		t.Fatalf("a satisfied probe with no error classified as %+v", got)
	}
}

func TestClassifyURLTestFailureSurvivesRewording(t *testing.T) {
	inner := &net.OpError{Op: "write", Err: syscall.EADDRNOTAVAIL}
	for _, prose := range []string{
		"dns resolve failed: %w",
		"all DNS requests failed, first error: %w",
		"could not work out where that name lives: %w",
		"%w",
	} {
		got := ClassifyURLTestFailure(fmt.Errorf(prose, inner), true, 0)
		if got.Kind != "write" || got.Errno != "EADDRNOTAVAIL" {
			t.Fatalf("wording %q changed the classification to kind=%q errno=%q", prose, got.Kind, got.Errno)
		}
	}
}
