//go:build darwin

package tunnel

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/ProjectClash/Clash/component/process"
	C "github.com/ProjectClash/Clash/constant"
)

func TestResolveMetadataAttributesTheConnectionToThisProcess(t *testing.T) {
	withDoorTestTunnel(t, "DIRECT")
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	go func() {
		if accepted, err := listener.Accept(); err == nil {
			defer accepted.Close()
		}
	}()

	conn, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	local := conn.LocalAddr().(*net.TCPAddr).AddrPort()
	remote := conn.RemoteAddr().(*net.TCPAddr).AddrPort()

	previousMode, previousFindProcess := Mode(), FindProcessMode()
	t.Cleanup(func() {
		SetMode(previousMode)
		SetFindProcessMode(previousFindProcess)
	})
	SetMode(Direct)
	SetFindProcessMode(process.FindProcessAlways)

	metadata := &C.Metadata{
		NetWork: C.TCP,
		Type:    C.TUN,
		SrcIP:   local.Addr().Unmap(),
		SrcPort: local.Port(),
		DstIP:   remote.Addr().Unmap(),
		DstPort: remote.Port(),
	}
	if _, _, err := resolveMetadata(metadata); err != nil {
		t.Fatalf("resolveMetadata: %v", err)
	}

	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("executable: %v", err)
	}
	if executable, err = filepath.EvalSymlinks(executable); err != nil {
		t.Fatalf("resolve executable: %v", err)
	}
	if metadata.ProcessPath != executable {
		t.Errorf("ProcessPath = %q, want %q -- the socket belongs to this test process",
			metadata.ProcessPath, executable)
	}
	if metadata.Process != filepath.Base(executable) {
		t.Errorf("Process = %q, want %q", metadata.Process, filepath.Base(executable))
	}
	if !metadata.UidKnown {
		t.Error("UidKnown = false; a resolved owner must mark the uid present, or UID rules defer")
	}
	if metadata.Uid != uint32(os.Getuid()) {
		t.Errorf("Uid = %d, want %d", metadata.Uid, os.Getuid())
	}
	if !metadata.SourceIdentityKnown {
		t.Error("SourceIdentityKnown = false; UID rules need it set to match exactly")
	}
}

func TestTheCallSiteReadsThePredicateAndNotTheTag(t *testing.T) {
	withDoorTestTunnel(t, "DIRECT")
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	go func() {
		if accepted, err := listener.Accept(); err == nil {
			defer accepted.Close()
		}
	}()

	conn, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	local := conn.LocalAddr().(*net.TCPAddr).AddrPort()
	remote := conn.RemoteAddr().(*net.TCPAddr).AddrPort()

	previousMode, previousFindProcess := Mode(), FindProcessMode()
	previousPredicate := resolvesOwnerByPackageName
	t.Cleanup(func() {
		SetMode(previousMode)
		SetFindProcessMode(previousFindProcess)
		resolvesOwnerByPackageName = previousPredicate
	})
	SetMode(Direct)
	SetFindProcessMode(process.FindProcessAlways)
	resolvesOwnerByPackageName = true

	metadata := &C.Metadata{
		NetWork: C.TCP,
		Type:    C.TUN,
		SrcIP:   local.Addr().Unmap(),
		SrcPort: local.Port(),
		DstIP:   remote.Addr().Unmap(),
		DstPort: remote.Port(),
	}
	if _, _, err := resolveMetadata(metadata); err != nil {
		t.Fatalf("resolveMetadata: %v", err)
	}

	if metadata.ProcessPath != "" {
		t.Errorf("ProcessPath = %q with resolvesOwnerByPackageName=true; the socket table was "+
			"read anyway, so the call site is not reading the predicate", metadata.ProcessPath)
	}
	if metadata.UidKnown || metadata.SourceIdentityKnown {
		t.Errorf("UidKnown=%v SourceIdentityKnown=%v with resolvesOwnerByPackageName=true; "+
			"the package-name branch supplies neither", metadata.UidKnown, metadata.SourceIdentityKnown)
	}
}
