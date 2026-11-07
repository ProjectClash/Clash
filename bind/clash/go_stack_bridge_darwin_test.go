package clash

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	C "github.com/ProjectClash/Clash/constant"
	LC "github.com/ProjectClash/Clash/listener/config"
	tun "github.com/metacubex/sing-tun"
	gobuf "github.com/sagernet/sing/common/buf"
	"golang.org/x/sys/unix"
)

func TestEveryHandedOverDescriptorRunsTheGoStack(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])
	for _, written := range []C.TUNStack{C.TunGo, C.TunMips, C.TunGvisor, C.TunSystem, C.TunMixed} {
		tun := LC.Tun{Stack: written}
		handOverTunDescriptor(&tun, fds[0])
		if tun.Stack != C.TunGo || tun.RecvMsgX {
			t.Errorf("a bridge handed %v over runs %v (batched reads %v), want go read plainly", written, tun.Stack, tun.RecvMsgX)
		}
	}
}

func startServiceOverTheBridge(t *testing.T, configuration string) (*BoxService, int, netip.Addr, *fdPlatform) {
	t.Helper()
	disarmThresholdMonitor(t, pressureThresholdShedEnabled.Load())
	base, err := os.MkdirTemp("/tmp", "clash-bridge-")
	if err != nil {
		t.Fatalf("short temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	if err := Setup(&SetupOptions{BasePath: base, WorkingPath: filepath.Join(base, "w"), TempPath: filepath.Join(base, "t")}); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fds[1]) })
	platform := &fdPlatform{
		recordingPlatform: recordingPlatform{lines: make(chan string, 256), underNetworkExtension: true},
		fd:                int32(fds[0]),
	}
	svc, err := NewService(platform)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	out, err := FinalizeForIOS(configuration, "{}")
	if err != nil {
		t.Fatalf("finalize: %v", err)
	}
	if err := svc.Start(out.Value); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	prefix, err := netip.ParsePrefix(platform.gotInet4)
	if err != nil {
		t.Fatalf("the tun's address %q: %v", platform.gotInet4, err)
	}
	if err := unix.SetsockoptTimeval(fds[1], unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 3}); err != nil {
		t.Fatal(err)
	}
	return svc, fds[1], prefix.Addr(), platform
}

func TestATunnelOverTheBridgeRunsTheGoStack(t *testing.T) {
	svc, app, source, _ := startServiceOverTheBridge(t, "tun:\n  enable: true\n  stack: gvisor\nproxies: []\nrules: ['MATCH,DIRECT']\n")

	var diagnostics map[string]any
	if err := json.Unmarshal([]byte(svc.RuntimeDiagnosticsJSON()), &diagnostics); err != nil {
		t.Fatal(err)
	}
	if got := diagnostics["tunStack"]; got != "Go" {
		t.Fatalf("a file that names gvisor runs %v over the bridge, want Go", got)
	}
	if got, _ := diagnostics["tunDescriptor"].(string); !strings.Contains(got, "PacketFlow bridge") {
		t.Fatalf("tunDescriptor %q, want the bridge", got)
	}

	destination := netip.MustParseAddr("1.1.1.1")
	echo := ipv4Echo(source, destination, 0x1234, 7, []byte("over the bridge"))
	if _, err := unix.Write(app, nil); err != nil {
		t.Fatalf("write an empty datagram to the bridge: %v", err)
	}
	if _, err := unix.Write(app, append([]byte{0, 0, 0, unix.AF_INET}, echo...)); err != nil {
		t.Fatalf("write to the bridge: %v", err)
	}
	frame := make([]byte, 65536)
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		n, err := unix.Read(app, frame)
		if err != nil {
			t.Fatalf("no echo reply came back over the bridge: %v", err)
		}
		if n < 4+28 || frame[3] != unix.AF_INET {
			continue
		}
		reply := frame[4:n]
		if reply[9] != unix.IPPROTO_ICMP || reply[20] != 0 {
			continue
		}
		if netip.AddrFrom4([4]byte(reply[12:16])) != destination || netip.AddrFrom4([4]byte(reply[16:20])) != source ||
			binary.BigEndian.Uint16(reply[24:]) != 0x1234 || string(reply[28:]) != "over the bridge" {
			t.Fatalf("the echo reply is not the request's: % x", reply)
		}
		return
	}
	t.Fatal("no echo reply came back over the bridge")
}

func ipv4Echo(from, to netip.Addr, id, sequence uint16, payload []byte) []byte {
	packet := make([]byte, 28+len(payload))
	packet[0], packet[8], packet[9] = 0x45, 64, unix.IPPROTO_ICMP
	binary.BigEndian.PutUint16(packet[2:], uint16(len(packet)))
	copy(packet[12:16], from.AsSlice())
	copy(packet[16:20], to.AsSlice())
	binary.BigEndian.PutUint16(packet[10:], internetChecksum(packet[:20]))
	packet[20] = 8
	binary.BigEndian.PutUint16(packet[24:], id)
	binary.BigEndian.PutUint16(packet[26:], sequence)
	copy(packet[28:], payload)
	binary.BigEndian.PutUint16(packet[22:], internetChecksum(packet[20:]))
	return packet
}

func internetChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i:]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum > 0xffff {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

func TestAConfiguredIPRewriteLineTakesPacketsOnTheTunnel(t *testing.T) {
	t.Cleanup(func() { tun.SetIPRewrite(nil) })
	_, app, source, _ := startServiceOverTheBridge(t, "tun:\n  enable: true\nx-clash-ip-rewrite:\n  - 10.9.0.0/16 = reflect\nproxies: []\nrules: ['MATCH,DIRECT']\n")
	destination := netip.MustParseAddrPort("10.9.0.1:53")
	datagram := ipv4UDP(netip.AddrPortFrom(source, 5000), destination, []byte("reflect me"))
	if _, err := unix.Write(app, append([]byte{0, 0, 0, unix.AF_INET}, datagram...)); err != nil {
		t.Fatalf("write to the bridge: %v", err)
	}
	frame := make([]byte, 65536)
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		n, err := unix.Read(app, frame)
		if err != nil {
			t.Fatalf("the datagram did not come back over the bridge: %v", err)
		}
		packet := frame[4:n]
		if n < 4+28 || packet[9] != unix.IPPROTO_UDP {
			continue
		}
		if netip.AddrFrom4([4]byte(packet[12:16])) != destination.Addr() || netip.AddrFrom4([4]byte(packet[16:20])) != source || string(packet[28:]) != "reflect me" {
			t.Fatalf("the datagram came back as % x", packet[:min(len(packet), 40)])
		}
		return
	}
	t.Fatal("the datagram did not come back over the bridge")
}

func TestABridgeWhoseOtherEndIsGoneIsReportedFailed(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	reported := make(chan error, 4)
	device, err := tun.New(tun.Options{FileDescriptor: fds[0], MTU: 1500, DeviceFailure: func(err error) { reported <- err }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = device.Close() })
	bridge := newGoStackBridge(device, 1500)
	t.Cleanup(func() { _ = bridge.Close() })
	if err := unix.Close(fds[1]); err != nil {
		t.Fatal(err)
	}
	packet := gobuf.NewSize(goStackBridgeHeader + 28)
	packet.Resize(goStackBridgeHeader, 0)
	_, _ = packet.Write(ipv4UDP(netip.MustParseAddrPort("1.1.1.1:53"), netip.MustParseAddrPort("198.18.0.2:5000"), nil))
	bridge.toApp([]*gobuf.Buffer{packet})
	select {
	case err := <-reported:
		if !errors.Is(err, syscall.ECONNRESET) {
			t.Fatalf("the owner was told %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a bridge whose other end is gone was never reported failed")
	}
}
