package clash

import (
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/component/process"
)

type heldOwnerResolver struct {
	letGo           chan struct{}
	in, most, calls atomic.Int32
	owner           *ConnectionOwner
}

func newHeldOwnerResolver() *heldOwnerResolver {
	return &heldOwnerResolver{letGo: make(chan struct{}), owner: &ConnectionOwner{UserId: 501, ProcessPath: "/Applications/Some.app/Contents/MacOS/Some"}}
}

func (h *heldOwnerResolver) FindConnectionOwner(int32, string, int32, string, int32) (*ConnectionOwner, error) {
	h.calls.Add(1)
	in := h.in.Add(1)
	for {
		most := h.most.Load()
		if in <= most || h.most.CompareAndSwap(most, in) {
			break
		}
	}
	<-h.letGo
	h.in.Add(-1)
	return h.owner, nil
}

func (h *heldOwnerResolver) settled() int32 {
	last, since := int32(-1), time.Now()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		if in := h.in.Load(); in != last {
			last, since = in, time.Now()
		} else if time.Since(since) >= 100*time.Millisecond {
			break
		}
	}
	return last
}

type slowOwnerResolver struct {
	after           time.Duration
	calls, returned atomic.Int32
	owner           *ConnectionOwner
}

func (s *slowOwnerResolver) FindConnectionOwner(int32, string, int32, string, int32) (*ConnectionOwner, error) {
	s.calls.Add(1)
	time.Sleep(s.after)
	s.returned.Add(1)
	return s.owner, nil
}

type ownerAnswer struct {
	path string
	err  error
	took time.Duration
}

func askOwnerBound(bound *ownerBound, resolver ConnectionOwnerResolver, network string, port int, answers chan<- ownerAnswer) {
	began := time.Now()
	_, path, err := bound.find(resolver, network, ownerSource, port, ownerDestination, 443)
	answers <- ownerAnswer{path, err, time.Since(began)}
}

func TestTheCoresBoundIsThePlatforms(t *testing.T) {
	b := &platformOwnerBound
	if b.atOnce != 4 || b.waiting != 1024 || b.deadline != 150*time.Millisecond || b.leastExchange != 15*time.Millisecond {
		t.Fatalf("the bound is %d at once, %d waiting, %v a lookup, %v least; want 4, 1024, 150ms, 15ms", b.atOnce, b.waiting, b.deadline, b.leastExchange)
	}
	if b.remembered != 2*time.Second {
		t.Fatalf("a UDP socket's owner is remembered %v, want 2s", b.remembered)
	}
}

func TestThePlatformIsAskedByAFewConnectionsAtOnce(t *testing.T) {
	withRuntimeProfile(t, runtimeProfileMacOSPacketTunnel)
	held := newHeldOwnerResolver()
	installOwnerResolver(t, held)
	var asking sync.WaitGroup
	for i := 0; i < 300; i++ {
		asking.Add(1)
		go func(port int) {
			defer asking.Done()
			_, _, _ = process.FindConnectionOwner(process.TCP, ownerSource, port, ownerDestination, 443)
		}(40000 + i)
	}
	if in := held.settled(); int(in) != platformOwnerBound.atOnce {
		t.Errorf("with 300 connections asking, the platform is in %d lookups at once, want %d", in, platformOwnerBound.atOnce)
	}
	gone := make(chan struct{})
	go func() { asking.Wait(); close(gone) }()
	select {
	case <-gone:
	case <-time.After(2 * time.Second):
		t.Errorf("300 connections are still waiting on a platform that does not answer, 2 s after they asked")
	}
	if calls := held.calls.Load(); int(calls) != platformOwnerBound.atOnce {
		t.Errorf("the platform was asked %d times while it did not answer, want %d", calls, platformOwnerBound.atOnce)
	}
	close(held.letGo)
	<-gone
	if most := held.most.Load(); int(most) > platformOwnerBound.atOnce {
		t.Fatalf("the platform was in %d lookups at once, want no more than %d", most, platformOwnerBound.atOnce)
	}
	for deadline := time.Now().Add(2 * time.Second); len(platformOwnerBound.places) > 0 && time.Now().Before(deadline); {
		time.Sleep(5 * time.Millisecond)
	}
	if taken := len(platformOwnerBound.places); taken != 0 {
		t.Fatalf("%d places still taken after the platform answered", taken)
	}
}

func TestAConnectionIsNotHeldPastItsDeadline(t *testing.T) {
	bound := &ownerBound{atOnce: 2, waiting: 8, deadline: 100 * time.Millisecond, leastExchange: 10 * time.Millisecond, remembered: time.Second}
	held := newHeldOwnerResolver()
	defer close(held.letGo)
	answers := make(chan ownerAnswer, 5)
	for i := 0; i < 5; i++ {
		go askOwnerBound(bound, held, process.TCP, 40000+i, answers)
	}
	for i := 0; i < 5; i++ {
		select {
		case a := <-answers:
			if a.err == nil || a.path != "" {
				t.Fatalf("a connection the platform did not answer was answered %q, %v", a.path, a.err)
			}
			if a.took < 80*time.Millisecond || a.took > 600*time.Millisecond {
				t.Fatalf("a connection the platform did not answer waited %v, want about 100 ms", a.took)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("%d of 5 connections are still waiting on a platform that does not answer", 5-i)
		}
	}
	if calls := held.calls.Load(); calls != 2 {
		t.Fatalf("the platform was asked %d times, want 2: the ones that had a place", calls)
	}
}

func TestFlowsOfOneSocketWaitNoLongerThanTheirDeadline(t *testing.T) {
	bound := &ownerBound{atOnce: 4, waiting: 32, deadline: 100 * time.Millisecond, leastExchange: 10 * time.Millisecond, remembered: time.Second}
	held := newHeldOwnerResolver()
	defer close(held.letGo)
	answers := make(chan ownerAnswer, 20)
	for i := 0; i < 20; i++ {
		go askOwnerBound(bound, held, process.UDP, 50000, answers)
	}
	for i := 0; i < 20; i++ {
		select {
		case a := <-answers:
			if a.err == nil || a.took > 600*time.Millisecond {
				t.Fatalf("a flow of a socket the platform did not answer was answered %q, %v after %v", a.path, a.err, a.took)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("%d of 20 flows of one socket are still waiting on a platform that does not answer", 20-i)
		}
	}
	if calls := held.calls.Load(); calls != 1 {
		t.Fatalf("twenty flows of one socket asked the platform %d times, want once", calls)
	}
}

func TestOnlySoManyWaitForAPlace(t *testing.T) {
	bound := &ownerBound{atOnce: 1, waiting: 3, deadline: 2 * time.Second, leastExchange: 10 * time.Millisecond, remembered: time.Second}
	held := newHeldOwnerResolver()
	answers := make(chan ownerAnswer, 4)
	go askOwnerBound(bound, held, process.TCP, 40000, answers)
	if in := held.settled(); in != 1 {
		t.Fatalf("the platform is in %d lookups, want the one", in)
	}
	for i := 1; i <= 3; i++ {
		go askOwnerBound(bound, held, process.TCP, 40000+i, answers)
	}
	time.Sleep(100 * time.Millisecond)
	began := time.Now()
	_, path, err := bound.find(held, process.TCP, ownerSource, 40099, ownerDestination, 443)
	if took := time.Since(began); err == nil || path != "" || took > 50*time.Millisecond {
		t.Fatalf("the connection past those waiting was answered %q, %v after %v, want no owner at once", path, err, took)
	}
	if calls := held.calls.Load(); calls != 1 {
		t.Fatalf("the platform was asked %d times, want the one with the place", calls)
	}
	close(held.letGo)
	for i := 0; i < 4; i++ {
		if a := <-answers; a.err != nil || a.path != held.owner.ProcessPath {
			t.Fatalf("a connection that had a place, or waited for one, was answered %q, %v", a.path, a.err)
		}
	}
}

func TestThoseWhoStopWaitingLeaveRoomToWait(t *testing.T) {
	bound := &ownerBound{atOnce: 1, waiting: 2, deadline: 2 * time.Second, leastExchange: 10 * time.Millisecond, remembered: time.Second}
	for wave := 0; wave < 3; wave++ {
		held := newHeldOwnerResolver()
		answers := make(chan ownerAnswer, 3)
		go askOwnerBound(bound, held, process.TCP, 40000+10*wave, answers)
		if in := held.settled(); in != 1 {
			t.Fatalf("wave %d: the platform is in %d lookups, want the one", wave, in)
		}
		for i := 1; i <= 2; i++ {
			go askOwnerBound(bound, held, process.TCP, 40000+10*wave+i, answers)
		}
		time.Sleep(50 * time.Millisecond)
		close(held.letGo)
		for i := 0; i < 3; i++ {
			if a := <-answers; a.err != nil || a.path != held.owner.ProcessPath {
				t.Fatalf("wave %d: a connection that had a place, or room to wait for one, was answered %q, %v", wave, a.path, a.err)
			}
		}
	}
}

func TestOnlyAnOwnerWithAPathIsAnAnswer(t *testing.T) {
	for _, fake := range []*fakeOwnerResolver{
		{err: errors.New("the App is not running")},
		{owner: nil},
		{owner: &ConnectionOwner{UserId: 501}},
	} {
		bound := &ownerBound{atOnce: 4, waiting: 32, deadline: 5 * time.Second, leastExchange: 10 * time.Millisecond, remembered: time.Minute}
		for i := 0; i < 2; i++ {
			if uid, path, err := bound.find(fake, process.UDP, ownerSource, 50300, ownerDestination, 443); err == nil || path != "" || uid != 0 {
				t.Fatalf("%+v was taken for an answer: uid %d, %q, %v", fake, uid, path, err)
			}
		}
		if calls := fake.calls.Load(); calls != 2 {
			t.Fatalf("a UDP socket's two flows asked %d times after no answer, want both", calls)
		}
	}
}

func TestALookupIsNotBegunWithTooLittleTimeLeft(t *testing.T) {
	bound := &ownerBound{atOnce: 1, waiting: 4, deadline: 300 * time.Millisecond, leastExchange: 150 * time.Millisecond, remembered: time.Second}
	held := newHeldOwnerResolver()
	answers := make(chan ownerAnswer, 2)
	go askOwnerBound(bound, held, process.TCP, 40000, answers)
	if in := held.settled(); in != 1 {
		t.Fatalf("the platform is in %d lookups, want the one", in)
	}
	go askOwnerBound(bound, held, process.TCP, 40001, answers)
	time.Sleep(200 * time.Millisecond)
	close(held.letGo)
	for i := 0; i < 2; i++ {
		<-answers
	}
	if calls := held.calls.Load(); calls != 1 {
		t.Fatalf("the platform was asked %d times, want only the one that had a place in time", calls)
	}
}

func TestAnAnswerThatArrivesLateIsRememberedForAUDPSocket(t *testing.T) {
	bound := &ownerBound{atOnce: 4, waiting: 32, deadline: 50 * time.Millisecond, leastExchange: 5 * time.Millisecond, remembered: time.Minute}
	slow := &slowOwnerResolver{after: 200 * time.Millisecond, owner: &ConnectionOwner{UserId: 501, ProcessPath: "/late"}}
	if _, path, err := bound.find(slow, process.UDP, ownerSource, 50000, ownerDestination, 443); err == nil || path != "" {
		t.Fatalf("a connection whose answer came after its deadline was answered %q, %v", path, err)
	}
	for deadline := time.Now().Add(2 * time.Second); slow.returned.Load() == 0 && time.Now().Before(deadline); {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	if _, path, err := bound.find(slow, process.UDP, ownerSource, 50000, ownerDestination, 53); err != nil || path != "/late" || slow.calls.Load() != 1 {
		t.Fatalf("the socket's next flow was answered %q, %v with the platform asked %d times, want the late answer and once", path, err, slow.calls.Load())
	}
}

func TestFlowsOfOneSocketAskThePlatformOnce(t *testing.T) {
	bound := &ownerBound{atOnce: 8, waiting: 32, deadline: 5 * time.Second, leastExchange: 10 * time.Millisecond, remembered: time.Second}
	held := newHeldOwnerResolver()
	var asking sync.WaitGroup
	paths := make(chan string, 50)
	for i := 0; i < 50; i++ {
		asking.Add(1)
		go func(i int) {
			defer asking.Done()
			_, path, _ := bound.find(held, process.UDP, ownerSource, 50000, netip.AddrFrom4([4]byte{203, 0, 113, byte(i)}), 443)
			paths <- path
		}(i)
	}
	if in := held.settled(); in != 1 {
		t.Errorf("fifty flows of one socket put the platform in %d lookups, want 1", in)
	}
	close(held.letGo)
	asking.Wait()
	close(paths)
	for path := range paths {
		if path != held.owner.ProcessPath {
			t.Fatalf("a flow of the socket was answered %q, want the owner the one lookup found", path)
		}
	}
	if calls := held.calls.Load(); calls != 1 {
		t.Fatalf("the platform was asked %d times, want once", calls)
	}
}

func TestAnOwnerFoundIsRememberedForItsSocketAShortWhile(t *testing.T) {
	bound := &ownerBound{atOnce: 8, waiting: 32, deadline: 5 * time.Second, leastExchange: 10 * time.Millisecond, remembered: 80 * time.Millisecond}
	fake := &fakeOwnerResolver{owner: &ConnectionOwner{UserId: 501, ProcessPath: "/Applications/Some.app/Contents/MacOS/Some"}}
	ask := func(network string, port int) {
		t.Helper()
		if _, path, err := bound.find(fake, network, ownerSource, port, ownerDestination, 443); err != nil || path != fake.owner.ProcessPath {
			t.Fatalf("answered %q, %v", path, err)
		}
	}
	ask(process.UDP, 50000)
	ask(process.UDP, 50000)
	if calls := fake.calls.Load(); calls != 1 {
		t.Fatalf("two flows of one socket in a row asked the platform %d times, want once", calls)
	}
	ask(process.UDP, 50001)
	ask(process.TCP, 50000)
	if calls := fake.calls.Load(); calls != 3 {
		t.Fatalf("after another port and the other protocol the platform was asked %d times, want 3", calls)
	}
	time.Sleep(120 * time.Millisecond)
	ask(process.UDP, 50000)
	if calls := fake.calls.Load(); calls != 4 {
		t.Fatalf("after the while had passed the platform was asked %d times in all, want 4", calls)
	}
}

func TestWhatIsRememberedGoesWhenItsWhileHasPassed(t *testing.T) {
	bound := &ownerBound{atOnce: 8, waiting: 32, deadline: 5 * time.Second, leastExchange: 10 * time.Millisecond, remembered: 30 * time.Millisecond}
	fake := &fakeOwnerResolver{owner: &ConnectionOwner{ProcessPath: "/x"}}
	for port := 0; port < 2000; port++ {
		_, _, _ = bound.find(fake, process.UDP, ownerSource, 1024+port, ownerDestination, 443)
	}
	bound.mu.Lock()
	kept := len(bound.known)
	bound.mu.Unlock()
	if kept < 1 || kept > 2000 {
		t.Fatalf("%d owners are remembered right after 2000 sockets asked", kept)
	}
	time.Sleep(60 * time.Millisecond)
	_, _, _ = bound.find(fake, process.UDP, ownerSource, 9, ownerDestination, 443)
	bound.mu.Lock()
	kept = len(bound.known)
	bound.mu.Unlock()
	if kept != 1 {
		t.Fatalf("%d owners are remembered after their while had passed, want the one just found", kept)
	}
}

func TestRegisteringAResolverForgetsWhatTheLastOneAnswered(t *testing.T) {
	withRuntimeProfile(t, runtimeProfileMacOSPacketTunnel)
	first := &fakeOwnerResolver{owner: &ConnectionOwner{ProcessPath: "/first"}}
	installOwnerResolver(t, first)
	if _, path, _ := process.FindConnectionOwner(process.UDP, ownerSource, 52100, ownerDestination, 443); path != "/first" {
		t.Fatalf("the first resolver's answer came back as %q", path)
	}
	second := &fakeOwnerResolver{owner: &ConnectionOwner{ProcessPath: "/second"}}
	installOwnerResolver(t, second)
	if _, path, _ := process.FindConnectionOwner(process.UDP, ownerSource, 52100, ownerDestination, 443); path != "/second" || second.calls.Load() != 1 {
		t.Fatalf("after another resolver was registered the same socket was answered %q, the new resolver asked %d times", path, second.calls.Load())
	}
}

func TestATCPSocketsOwnerIsNotRemembered(t *testing.T) {
	bound := &ownerBound{atOnce: 8, waiting: 32, deadline: 5 * time.Second, leastExchange: 10 * time.Millisecond, remembered: time.Minute}
	fake := &fakeOwnerResolver{owner: &ConnectionOwner{UserId: 501, ProcessPath: "/first"}}
	if _, path, _ := bound.find(fake, process.TCP, ownerSource, 51000, ownerDestination, 443); path != "/first" {
		t.Fatalf("answered %q", path)
	}
	fake.owner = &ConnectionOwner{UserId: 502, ProcessPath: "/second"}
	uid, path, _ := bound.find(fake, process.TCP, ownerSource, 51000, ownerDestination, 443)
	if path != "/second" || uid != 502 || fake.calls.Load() != 2 {
		t.Fatalf("the port's next connection was answered %q (uid %d) with the platform asked %d times, want the platform's new answer", path, uid, fake.calls.Load())
	}
}

func TestWhatIsRememberedIsTheSocketsAndAllOfTheAnswer(t *testing.T) {
	bound := &ownerBound{atOnce: 8, waiting: 32, deadline: 5 * time.Second, leastExchange: 10 * time.Millisecond, remembered: time.Minute}
	fake := &fakeOwnerResolver{owner: &ConnectionOwner{UserId: 501, ProcessPath: "/first"}}
	_, _, _ = bound.find(fake, process.UDP, ownerSource, 50000, ownerDestination, 443)
	if uid, path, err := bound.find(fake, process.UDP, ownerSource, 50000, ownerDestination, 53); uid != 501 || path != "/first" || err != nil || fake.calls.Load() != 1 {
		t.Fatalf("the socket's next flow was answered uid %d, %q, %v with the platform asked %d times", uid, path, err, fake.calls.Load())
	}
	other := netip.MustParseAddr("198.18.0.2")
	_, _, _ = bound.find(fake, process.UDP, other, 50000, ownerDestination, 443)
	if calls := fake.calls.Load(); calls != 2 {
		t.Fatalf("the same port of another address asked the platform %d times in all, want 2", calls)
	}
}

func TestEveryPlaceIsGivenBack(t *testing.T) {
	bound := &ownerBound{atOnce: 2, waiting: 8, deadline: 5 * time.Second, leastExchange: 10 * time.Millisecond, remembered: time.Second}
	for i, fake := range []*fakeOwnerResolver{
		{owner: &ConnectionOwner{ProcessPath: "/x"}},
		{err: errNoOwner},
		{owner: nil},
	} {
		for port := 0; port < 5; port++ {
			_, _, _ = bound.find(fake, process.TCP, ownerSource, 41000+10*i+port, ownerDestination, 443)
		}
	}
	if taken := len(bound.places); taken != 0 {
		t.Fatalf("%d places are still taken with no lookup in flight", taken)
	}
	late := &ownerBound{atOnce: 2, waiting: 8, deadline: 30 * time.Millisecond, leastExchange: 5 * time.Millisecond, remembered: time.Second}
	slow := &slowOwnerResolver{after: 100 * time.Millisecond, owner: &ConnectionOwner{ProcessPath: "/x"}}
	for port := 0; port < 2; port++ {
		_, _, _ = late.find(slow, process.TCP, ownerSource, 42000+port, ownerDestination, 443)
	}
	for deadline := time.Now().Add(2 * time.Second); slow.returned.Load() < 2 && time.Now().Before(deadline); {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	late.mu.Lock()
	taken, asking := len(late.places), len(late.asking)
	late.mu.Unlock()
	if taken != 0 || asking != 0 {
		t.Fatalf("%d places are still taken and %d lookups listed after the platform answered late", taken, asking)
	}
}

func TestAnAnswerOnItsWayWhenTheResolverChangesIsNotRemembered(t *testing.T) {
	bound := &ownerBound{atOnce: 8, waiting: 32, deadline: 5 * time.Second, leastExchange: 10 * time.Millisecond, remembered: time.Minute}
	held := newHeldOwnerResolver()
	held.owner = &ConnectionOwner{ProcessPath: "/old"}
	answered := make(chan string, 1)
	go func() {
		_, path, _ := bound.find(held, process.UDP, ownerSource, 50200, ownerDestination, 443)
		answered <- path
	}()
	if in := held.settled(); in != 1 {
		t.Fatalf("the platform is in %d lookups, want the one", in)
	}
	bound.forget(nil)
	close(held.letGo)
	if path := <-answered; path != "/old" {
		t.Fatalf("the flow that asked the old resolver was answered %q", path)
	}
	fresh := &fakeOwnerResolver{owner: &ConnectionOwner{ProcessPath: "/new"}}
	if _, path, _ := bound.find(fresh, process.UDP, ownerSource, 50200, ownerDestination, 443); path != "/new" || fresh.calls.Load() != 1 {
		t.Fatalf("the socket's next flow was answered %q with the new resolver asked %d times, want it asked", path, fresh.calls.Load())
	}
}

func TestALookupThroughAReplacedResolverIsNotAsked(t *testing.T) {
	withRuntimeProfile(t, runtimeProfileMacOSPacketTunnel)
	first := &fakeOwnerResolver{owner: &ConnectionOwner{ProcessPath: "/first"}}
	installOwnerResolver(t, first)
	old := platformOwnerResolver.Load()
	second := &fakeOwnerResolver{owner: &ConnectionOwner{ProcessPath: "/second"}}
	installOwnerResolver(t, second)
	if _, path, err := platformOwnerBound.findAs(old.resolver, old.generation, process.UDP, ownerSource, 52300, ownerDestination, 443); err == nil || path != "" || first.calls.Load() != 0 {
		t.Fatalf("a lookup through the replaced resolver was answered %q, %v with it asked %d times", path, err, first.calls.Load())
	}
	if _, path, _ := process.FindConnectionOwner(process.UDP, ownerSource, 52300, ownerDestination, 443); path != "/second" || second.calls.Load() != 1 {
		t.Fatalf("the socket's next flow was answered %q with the new resolver asked %d times", path, second.calls.Load())
	}
}

func TestAFlowAfterTheResolverChangesAsksTheNewOne(t *testing.T) {
	withRuntimeProfile(t, runtimeProfileMacOSPacketTunnel)
	held := newHeldOwnerResolver()
	held.owner = &ConnectionOwner{ProcessPath: "/old"}
	installOwnerResolver(t, held)
	defer close(held.letGo)
	go func() { _, _, _ = process.FindConnectionOwner(process.UDP, ownerSource, 52400, ownerDestination, 443) }()
	if in := held.settled(); in != 1 {
		t.Fatalf("the platform is in %d lookups, want the one", in)
	}
	fresh := &fakeOwnerResolver{owner: &ConnectionOwner{ProcessPath: "/new"}}
	installOwnerResolver(t, fresh)
	if _, path, _ := process.FindConnectionOwner(process.UDP, ownerSource, 52400, ownerDestination, 53); path != "/new" || fresh.calls.Load() != 1 {
		t.Fatalf("a flow after the change was answered %q with the new resolver asked %d times, want it asked", path, fresh.calls.Load())
	}
}

func TestAFlowThatJoinsALookupWaitingForAPlaceWaitsItsOwnDeadline(t *testing.T) {
	bound := &ownerBound{atOnce: 1, waiting: 4, deadline: 300 * time.Millisecond, leastExchange: 10 * time.Millisecond, remembered: time.Second}
	held := newHeldOwnerResolver()
	first := make(chan ownerAnswer, 1)
	go askOwnerBound(bound, held, process.TCP, 41000, first)
	if in := held.settled(); in != 1 {
		t.Fatalf("the platform is in %d lookups, want the one", in)
	}
	began := time.Now()
	early, late := make(chan ownerAnswer, 1), make(chan ownerAnswer, 1)
	go askOwnerBound(bound, held, process.UDP, 50500, early)
	time.Sleep(200 * time.Millisecond)
	go askOwnerBound(bound, held, process.UDP, 50500, late)
	time.Sleep(time.Until(began.Add(350 * time.Millisecond)))
	close(held.letGo)
	if a := <-early; a.err == nil {
		t.Fatalf("the flow whose deadline passed before a place came free was answered %q", a.path)
	}
	if a := <-late; a.err != nil || a.path != held.owner.ProcessPath {
		t.Fatalf("the flow that joined, with time left when a place came free, was answered %q, %v", a.path, a.err)
	}
	<-first
}

func TestWhatIsRememberedIsSweptOnceAWhile(t *testing.T) {
	bound := &ownerBound{atOnce: 8, waiting: 32, deadline: 5 * time.Second, leastExchange: 10 * time.Millisecond, remembered: time.Minute}
	fake := &fakeOwnerResolver{owner: &ConnectionOwner{ProcessPath: "/x"}}
	for port := 0; port < 500; port++ {
		_, _, _ = bound.find(fake, process.UDP, ownerSource, 1024+port, ownerDestination, 443)
	}
	bound.mu.Lock()
	sweeps, kept := bound.sweeps, len(bound.known)
	bound.mu.Unlock()
	if sweeps > 1 || kept != 500 {
		t.Fatalf("500 sockets answered within a while swept what is remembered %d times and keep %d, want at most once and 500", sweeps, kept)
	}
}

func TestThoseWhoGaveUpWaitingLeaveNothingBehind(t *testing.T) {
	bound := &ownerBound{atOnce: 1, waiting: 2, deadline: 60 * time.Millisecond, leastExchange: 10 * time.Millisecond, remembered: time.Second}
	held := newHeldOwnerResolver()
	first := make(chan ownerAnswer, 1)
	go askOwnerBound(bound, held, process.TCP, 40000, first)
	if in := held.settled(); in != 1 {
		t.Fatalf("the platform is in %d lookups, want the one", in)
	}
	for wave := 0; wave < 3; wave++ {
		answers := make(chan ownerAnswer, 2)
		for i := 1; i <= 2; i++ {
			go askOwnerBound(bound, held, process.TCP, 40000+i, answers)
		}
		for i := 0; i < 2; i++ {
			if a := <-answers; a.err == nil || a.took < 40*time.Millisecond {
				t.Fatalf("wave %d: a connection with no place in time was answered %q, %v after %v", wave, a.path, a.err, a.took)
			}
		}
	}
	time.Sleep(20 * time.Millisecond)
	bound.mu.Lock()
	queued, listed := bound.queued, len(bound.asking)
	bound.mu.Unlock()
	if queued != 0 || listed != 1 {
		t.Fatalf("%d lookups counted waiting and %d listed after the waves gave up, want 0 and the one with the place", queued, listed)
	}
	close(held.letGo)
	<-first
	if _, path, err := bound.find(held, process.TCP, ownerSource, 40001, ownerDestination, 443); err != nil || path != held.owner.ProcessPath {
		t.Fatalf("a socket whose lookup gave up was answered %q, %v when it asked again", path, err)
	}
}

func TestALookupFromBeforeTheChangeLeavesTheNewOneListed(t *testing.T) {
	bound := &ownerBound{atOnce: 8, waiting: 32, deadline: 5 * time.Second, leastExchange: 10 * time.Millisecond, remembered: time.Minute}
	old, fresh := newHeldOwnerResolver(), newHeldOwnerResolver()
	go func() { _, _, _ = bound.find(old, process.TCP, ownerSource, 52500, ownerDestination, 443) }()
	if in := old.settled(); in != 1 {
		t.Fatalf("the old resolver is in %d lookups, want the one", in)
	}
	bound.forget(nil)
	answers := make(chan ownerAnswer, 2)
	go askOwnerBound(bound, fresh, process.TCP, 52500, answers)
	if in := fresh.settled(); in != 1 {
		t.Fatalf("the new resolver is in %d lookups, want the one", in)
	}
	close(old.letGo)
	for deadline := time.Now().Add(2 * time.Second); old.in.Load() > 0 && time.Now().Before(deadline); {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	go askOwnerBound(bound, fresh, process.TCP, 52500, answers)
	time.Sleep(50 * time.Millisecond)
	close(fresh.letGo)
	for i := 0; i < 2; i++ {
		if a := <-answers; a.err != nil || a.path != fresh.owner.ProcessPath {
			t.Fatalf("a flow after the change was answered %q, %v", a.path, a.err)
		}
	}
	if calls := fresh.calls.Load(); calls != 1 {
		t.Fatalf("the new resolver was asked %d times for one socket's two flows, want once", calls)
	}
}

type fastOwnerResolver struct {
	after time.Duration
	calls atomic.Int32
}

func (f *fastOwnerResolver) FindConnectionOwner(int32, string, int32, string, int32) (*ConnectionOwner, error) {
	f.calls.Add(1)
	time.Sleep(f.after)
	return &ConnectionOwner{UserId: 501, ProcessPath: "/Applications/Some.app/Contents/MacOS/Some"}, nil
}

func TestABurstThePlatformCanAnswerInTimeIsAnsweredWhole(t *testing.T) {
	withRuntimeProfile(t, runtimeProfileMacOSPacketTunnel)
	fast := &fastOwnerResolver{after: time.Millisecond}
	installOwnerResolver(t, fast)
	var asking sync.WaitGroup
	var owned, slowest atomic.Int64
	for i := 0; i < 300; i++ {
		asking.Add(1)
		go func(port int) {
			defer asking.Done()
			began := time.Now()
			_, path, err := process.FindConnectionOwner(process.TCP, ownerSource, port, ownerDestination, 443)
			took := int64(time.Since(began))
			for {
				most := slowest.Load()
				if took <= most || slowest.CompareAndSwap(most, took) {
					break
				}
			}
			if err == nil && path != "" {
				owned.Add(1)
			}
		}(43000 + i)
	}
	asking.Wait()
	if owned.Load() != 300 {
		t.Errorf("%d of 300 connections in a burst have their owner, with the platform answering each in 1 ms", owned.Load())
	}
	if most := time.Duration(slowest.Load()); most > platformOwnerBound.deadline+50*time.Millisecond {
		t.Errorf("the slowest connection waited %v; the deadline is %v", most, platformOwnerBound.deadline)
	}
}
