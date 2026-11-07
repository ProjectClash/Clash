package sing_tun

import (
	"errors"
	LC "github.com/ProjectClash/Clash/listener/config"
	"testing"
	"time"

	C "github.com/ProjectClash/Clash/constant"

	tun "github.com/metacubex/sing-tun"
)

func TestTheGoStackIsNamedGo(t *testing.T) {
	var stack C.TUNStack
	if err := stack.UnmarshalText([]byte("go")); err != nil {
		t.Fatalf("tun.stack go does not parse: %v", err)
	}
	if stack != C.TunGo || stack.String() != "Go" {
		t.Fatalf("tun.stack go parsed to %v (%q)", stack, stack.String())
	}
}

func TestTheGoStackIsBuiltByTheRegisteredFactory(t *testing.T) {
	SetGoStackFactory(nil)
	t.Cleanup(func() { SetGoStackFactory(nil) })
	if _, err := newGoStack(GoStackOptions{}); err == nil {
		t.Fatal("with no factory registered the go stack was built")
	}
	var got GoStackOptions
	SetGoStackFactory(func(options GoStackOptions) (tun.Stack, error) {
		got = options
		return nil, nil
	})
	want := GoStackOptions{UDPTimeout: 3 * time.Second, ICMPTimeout: 5 * time.Second, CongestionControl: "bbr"}
	if _, err := newGoStack(want); err != nil {
		t.Fatal(err)
	}
	if got.UDPTimeout != want.UDPTimeout || got.ICMPTimeout != want.ICMPTimeout || got.CongestionControl != "bbr" {
		t.Fatalf("the factory got %+v", got)
	}
}

type fakeGoStack struct {
	startErr error
	closed   bool
}

func (s *fakeGoStack) Start() error { return s.startErr }
func (s *fakeGoStack) Close() error { s.closed = true; return nil }

func TestAGoStackThatFailsToStartIsClosed(t *testing.T) {
	stack := &fakeGoStack{startErr: errors.New("no utun")}
	SetGoStackFactory(func(GoStackOptions) (tun.Stack, error) { return stack, nil })
	t.Cleanup(func() { SetGoStackFactory(nil) })
	if running, err := startGoStack(GoStackOptions{}); err == nil || running != nil {
		t.Fatalf("a go stack that failed to start came back as %v (%v)", running, err)
	}
	if !stack.closed {
		t.Fatal("a go stack that failed to start was left open")
	}
}

func TestStartGoStackRunsTheGoStackOrNone(t *testing.T) {
	t.Cleanup(func() { SetGoStackFactory(nil) })
	started := &fakeGoStack{}
	SetGoStackFactory(func(GoStackOptions) (tun.Stack, error) { return started, nil })
	if stack, err := startGoStack(GoStackOptions{}); err != nil || stack != started {
		t.Fatalf("a go stack that started came back as %v (%v)", stack, err)
	}
	SetGoStackFactory(nil)
	if stack, err := startGoStack(GoStackOptions{}); err == nil || stack != nil {
		t.Fatalf("with no factory registered a stack came back: %v (%v)", stack, err)
	}
}

func TestTheListenerReportsTheStackThatRuns(t *testing.T) {
	listener := &Listener{options: LC.Tun{Stack: C.TunGvisor}, tunStack: &fakeGoStack{}}
	if got := listener.Config().Stack; got != C.TunGo {
		t.Fatalf("a listener whose file wrote gVisor reports %v, want the go stack it runs", got)
	}
	unset := &Listener{options: LC.Tun{Stack: C.TunMips}}
	if got := unset.Config().Stack; got != C.TunMips {
		t.Fatalf("a listener that has not started reports %v, want what it was given", got)
	}
}
