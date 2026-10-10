package clash

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/config"
	"github.com/ProjectClash/Clash/hub/route"
	"github.com/ProjectClash/Clash/log"
)

func resetRemoteControlForTest(t *testing.T) {
	t.Helper()
	previousHost := remoteControlLANHost
	remoteControlLANHost = "127.0.0.1"
	resetRemoteControlState()
	t.Cleanup(func() {
		stopClashAPI("")
		resetRemoteControlState()
		remoteControlLANHost = previousHost
	})
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func testCertificate(t *testing.T) (certificate, key, fingerprint string) {
	t.Helper()
	var reply struct {
		CertificatePEM string `json:"certificatePEM"`
		PrivateKeyPEM  string `json:"privateKeyPEM"`
		Fingerprint    string `json:"fingerprint"`
		Error          string `json:"error"`
	}
	if err := json.Unmarshal([]byte(GenerateControllerCertificate()), &reply); err != nil || reply.Error != "" {
		t.Fatalf("GenerateControllerCertificate: %v %s", err, reply.Error)
	}
	return reply.CertificatePEM, reply.PrivateKeyPEM, reply.Fingerprint
}

type remoteControlReply struct {
	Generation int64  `json:"generation"`
	Mode       string `json:"mode"`
	Running    bool   `json:"running"`
	Error      string `json:"error"`
	HTTP       struct {
		Address string `json:"address"`
		Error   string `json:"error"`
	} `json:"http"`
	TLS struct {
		Address     string `json:"address"`
		Error       string `json:"error"`
		Fingerprint string `json:"fingerprint"`
	} `json:"tls"`
}

func apply(t *testing.T, settings map[string]any) remoteControlReply {
	t.Helper()
	data, _ := json.Marshal(settings)
	var reply remoteControlReply
	if err := json.Unmarshal([]byte(ApplyRemoteControl(string(data))), &reply); err != nil {
		t.Fatal(err)
	}
	return reply
}

func TestGenerateControllerCertificateIsUsableAndPinnedByItsDER(t *testing.T) {
	certificate, key, fingerprint := testCertificate(t)
	pair, err := tls.X509KeyPair([]byte(certificate), []byte(key))
	if err != nil {
		t.Fatalf("the generated pair does not load: %v", err)
	}
	block, _ := pem.Decode([]byte(certificate))
	parsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	_ = pair
	if key, ok := parsed.PublicKey.(*ecdsa.PublicKey); !ok || key.Curve != elliptic.P256() {
		t.Fatalf("want an ECDSA P-256 key, got %T", parsed.PublicKey)
	}
	sum := sha256.Sum256(block.Bytes)
	if want := formatControllerFingerprint(sum[:]); fingerprint != want {
		t.Fatalf("fingerprint %q, want the DER SHA-256 %q", fingerprint, want)
	}
	if !strings.HasPrefix(fingerprint, "sha256:") || len(fingerprint) != len("sha256:")+32*3-1 {
		t.Fatalf("fingerprint %q is not sha256:AB:CD:...", fingerprint)
	}
}

func TestRemoteControlSettingsAreValidated(t *testing.T) {
	resetRemoteControlForTest(t)
	certificate, key, _ := testCertificate(t)
	good := func(mode string) map[string]any {
		return map[string]any{"mode": mode, "httpPort": 9090, "tlsPort": 9443, "secret": "0123456789abcdef0123456789abcdef",
			"certificatePEM": certificate, "privateKeyPEM": key, "generation": 1}
	}
	for _, c := range []struct {
		name   string
		edit   func(map[string]any)
		reason string
	}{
		{"unknown mode", func(s map[string]any) { s["mode"] = "on" }, "mode"},
		{"port below range", func(s map[string]any) { s["httpPort"] = 80 }, "port"},
		{"port above range", func(s map[string]any) { s["tlsPort"] = 70000 }, "port"},
		{"same ports", func(s map[string]any) { s["tlsPort"] = 9090 }, "port"},
		{"no secret", func(s map[string]any) { s["secret"] = "" }, "secret"},
		{"secret with a space", func(s map[string]any) { s["secret"] = "a b" }, "secret"},
		{"broken certificate", func(s map[string]any) { s["certificatePEM"] = "nope" }, "certificate"},
	} {
		settings := good("lan")
		c.edit(settings)
		reply := apply(t, settings)
		if reply.Error == "" || !strings.Contains(reply.Error, c.reason) {
			t.Errorf("%s: error %q, want one naming %q", c.name, reply.Error, c.reason)
		}
	}
	if reply := apply(t, map[string]any{"mode": "config", "generation": 1}); reply.Error != "" {
		t.Fatalf("use-the-configuration needs nothing else, got %q", reply.Error)
	}
	if reply := apply(t, good("local")); reply.Error != "" {
		t.Fatalf("a complete local setting was refused: %q", reply.Error)
	}
}

func TestAnOlderGenerationIsRefusedAndTheCurrentOneKept(t *testing.T) {
	resetRemoteControlForTest(t)
	newer := map[string]any{"mode": "local", "httpPort": 9090, "secret": "s", "generation": 5}
	if reply := apply(t, newer); reply.Error != "" || reply.Generation != 5 {
		t.Fatalf("%+v", reply)
	}
	reply := apply(t, map[string]any{"mode": "config", "generation": 4})
	if reply.Error == "" || !strings.Contains(reply.Error, "generation") {
		t.Fatalf("an older generation was taken: %+v", reply)
	}
	if reply.Mode != "local" || reply.Generation != 5 {
		t.Fatalf("a refused apply changed the settings: %+v", reply)
	}
}

func TestLocalModeIsNotOfferedOnTheTelevision(t *testing.T) {
	resetRemoteControlForTest(t)
	withRuntimeProfile(t, runtimeProfileTVOSPacketTunnel)
	reply := apply(t, map[string]any{"mode": "local", "httpPort": 9090, "secret": "s", "generation": 1})
	if reply.Error == "" {
		t.Fatal("tvOS has no loopback consumer; local must be refused there")
	}
}

func TestTheMergeIsFieldByField(t *testing.T) {
	certificate, key, _ := testCertificate(t)
	base := &route.Config{
		Addr: "0.0.0.0:9090", TLSAddr: "0.0.0.0:9091", UnixAddr: "/g/clash.sock", Secret: "config-secret",
		Certificate: "config-cert", PrivateKey: "config-key", ClientAuthType: "require-and-verify",
		ClientAuthCert: "ca", EchKey: "ech", DohServer: "/dns-query", IsDebug: true,
		Cors: route.Cors{AllowOrigins: []string{"https://ui.example"}, AllowPrivateNetwork: true},
	}
	settings := remoteControlSettings{Mode: remoteControlLocal, HTTPPort: 9190, TLSPort: 9543, Secret: "app",
		CertificatePEM: certificate, PrivateKeyPEM: key}

	if got := mergeRemoteControl(base, remoteControlSettings{Mode: remoteControlConfig}, runtimeProfileIOSPacketTunnel); !reflect.DeepEqual(got, base) {
		t.Fatalf("use-the-configuration changed the controller:\n got %+v\nwant %+v", got, base)
	}

	local := mergeRemoteControl(base, settings, runtimeProfileIOSPacketTunnel)
	if local.Addr != "127.0.0.1:9190" || local.TLSAddr != "" || local.Secret != "app" || !local.Managed {
		t.Fatalf("local: %+v", local)
	}
	if local.Certificate != "" || local.PrivateKey != "" || local.ClientAuthType != "" || local.ClientAuthCert != "" ||
		local.EchKey != "" || local.DohServer != "" {
		t.Fatalf("local carried the configuration's TLS, client auth, ECH or DoH: %+v", local)
	}
	if local.UnixAddr != base.UnixAddr || !reflect.DeepEqual(local.Cors, base.Cors) || local.IsDebug != base.IsDebug {
		t.Fatalf("local must keep the App Group socket, CORS and the debug switch: %+v", local)
	}

	settings.Mode = remoteControlLAN
	lan := mergeRemoteControl(base, settings, runtimeProfileIOSPacketTunnel)
	if lan.Addr != "127.0.0.1:9190" || lan.TLSAddr != remoteControlLANHost+":9543" || lan.Secret != "app" ||
		lan.Certificate != certificate || lan.PrivateKey != key || lan.ClientAuthType != "" || lan.EchKey != "" || !lan.Managed {
		t.Fatalf("lan: %+v", lan)
	}
	if lan.AcceptFilter == nil {
		t.Fatal("lan must only accept local-network sources (D2a)")
	}
	tv := mergeRemoteControl(base, settings, runtimeProfileTVOSPacketTunnel)
	if tv.Addr != "" || tv.TLSAddr == "" {
		t.Fatalf("the television opens TLS only: %+v", tv)
	}
	macLAN := mergeRemoteControl(base, settings, runtimeProfileMacOSPacketTunnel)
	if macLAN.Addr != "127.0.0.1:9190" {
		t.Fatalf("macOS lan keeps the loopback HTTP listener: %+v", macLAN)
	}
}

func TestLANAcceptsOnlyLocalNetworkSources(t *testing.T) {
	filter := mergeRemoteControl(&route.Config{}, remoteControlSettings{Mode: remoteControlLAN, HTTPPort: 9090, TLSPort: 9443, Secret: "s"},
		runtimeProfileIOSPacketTunnel).AcceptFilter
	for address, want := range map[string]bool{
		"192.168.1.20:5000": true, "10.0.0.2:5000": true, "172.20.10.2:5000": true, "127.0.0.1:5000": true,
		"[fe80::1]:5000": true, "[fd00::5]:5000": true,
		"8.8.8.8:5000": false, "[2409:8a00::1]:5000": false, "100.64.0.1:5000": false,
	} {
		addr, err := net.ResolveTCPAddr("tcp", address)
		if err != nil {
			t.Fatal(err)
		}
		if got := filter(addr); got != want {
			t.Errorf("%s admitted=%v, want %v", address, got, want)
		}
	}
}

func liveControlPlane(t *testing.T, cfg *config.Config) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "rc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "c.sock")
	recreateControlPlane(cfg, socket)
	if err := secureBindingControlSocket(socket); err != nil {
		t.Fatal(err)
	}
	return socket
}

func unixGet(t *testing.T, socket, path string) int {
	t.Helper()
	client := http.Client{Transport: &http.Transport{Dial: func(string, string) (net.Conn, error) { return net.Dial("unix", socket) }}}
	response, err := client.Get("http://unix" + path)
	if err != nil {
		t.Fatalf("unix GET %s: %v", path, err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	return response.StatusCode
}

func tcpGet(address, path, secret string) (int, error) {
	request, _ := http.NewRequest(http.MethodGet, "http://"+address+path, nil)
	if secret != "" {
		request.Header.Set("Authorization", "Bearer "+secret)
	}
	response, err := (&http.Client{Timeout: 2 * time.Second}).Do(request)
	if err != nil {
		return 0, err
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	return response.StatusCode, nil
}

func TestApplyBeforeTheControlPlaneOnlyRecords(t *testing.T) {
	resetRemoteControlForTest(t)
	port := freePort(t)
	reply := apply(t, map[string]any{"mode": "local", "httpPort": port, "secret": "s", "generation": 1})
	if reply.Error != "" || reply.Running {
		t.Fatalf("%+v", reply)
	}
	if _, err := tcpGet(fmt.Sprintf("127.0.0.1:%d", port), "/version", "s"); err == nil {
		t.Fatal("something listens before the control plane started")
	}
	merged := controllerServerConfig(&config.Config{}, "")
	if merged.Addr != fmt.Sprintf("127.0.0.1:%d", port) || merged.Secret != "s" {
		t.Fatalf("the next control plane will not carry the recorded setting: %+v", merged)
	}
}

func TestApplyWhileLiveReplacesTCPAndTLSOnly(t *testing.T) {
	resetRemoteControlForTest(t)
	socket := liveControlPlane(t, &config.Config{})
	before, _ := os.Stat(socket)
	certificate, key, fingerprint := testCertificate(t)
	httpPort, tlsPort := freePort(t), freePort(t)

	reply := apply(t, map[string]any{"mode": "lan", "httpPort": httpPort, "tlsPort": tlsPort, "secret": "app",
		"certificatePEM": certificate, "privateKeyPEM": key, "generation": 1})
	if reply.Error != "" || !reply.Running || reply.HTTP.Error != "" || reply.TLS.Error != "" {
		t.Fatalf("%+v", reply)
	}
	if reply.TLS.Fingerprint != fingerprint {
		t.Fatalf("status fingerprint %q, want %q", reply.TLS.Fingerprint, fingerprint)
	}
	if code, err := tcpGet(reply.HTTP.Address, "/version", ""); err != nil || code != http.StatusUnauthorized {
		t.Fatalf("no secret: %d %v", code, err)
	}
	if code, err := tcpGet(reply.HTTP.Address, "/version", "app"); err != nil || code != http.StatusOK {
		t.Fatalf("the App's secret: %d %v", code, err)
	}
	conn, err := tls.Dial("tcp", reply.TLS.Address, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("TLS listener: %v", err)
	}
	sum := sha256.Sum256(conn.ConnectionState().PeerCertificates[0].Raw)
	_ = conn.Close()
	if formatControllerFingerprint(sum[:]) != fingerprint {
		t.Fatal("the TLS listener does not present the App's certificate")
	}

	after, err := os.Stat(socket)
	if err != nil || !os.SameFile(before, after) || after.Mode().Perm() != 0o600 {
		t.Fatalf("the App Group socket was touched: %v %v", err, after)
	}
	if code := unixGet(t, socket, "/version"); code != http.StatusOK {
		t.Fatalf("unix /version = %d", code)
	}

	reply = apply(t, map[string]any{"mode": "config", "generation": 2})
	if reply.HTTP.Address != "" || reply.TLS.Address != "" {
		t.Fatalf("back to the configuration, which names no controller: %+v", reply)
	}
	if _, err := tcpGet(fmt.Sprintf("127.0.0.1:%d", httpPort), "/version", "app"); err == nil {
		t.Fatal("the App's listener still answers after the setting went back to the configuration")
	}
}

func TestChangingTheSecretEndsStreamsOpenedWithTheOldOne(t *testing.T) {
	resetRemoteControlForTest(t)
	liveControlPlane(t, &config.Config{})
	port := freePort(t)
	reply := apply(t, map[string]any{"mode": "local", "httpPort": port, "secret": "old", "generation": 1})

	conn, err := net.Dial("tcp", reply.HTTP.Address)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "GET /traffic HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\nAuthorization: Bearer old\r\n\r\n",
		base64.StdEncoding.EncodeToString([]byte("0123456789abcdef")))
	reader := bufio.NewReader(conn)
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if line, err := reader.ReadString('\n'); err != nil || !strings.Contains(line, "101") {
		t.Fatalf("upgrade: %q %v", line, err)
	}
	readThroughHeadersAndOneFrame(t, reader)

	apply(t, map[string]any{"mode": "local", "httpPort": port, "secret": "new", "generation": 2})
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.Copy(io.Discard, reader); err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			t.Fatal("a stream opened with the old secret kept running after the secret changed")
		}
	}
}

func TestCloseForgetsTheControlPlane(t *testing.T) {
	resetRemoteControlForTest(t)
	liveControlPlane(t, &config.Config{})
	port := freePort(t)
	apply(t, map[string]any{"mode": "local", "httpPort": port, "secret": "s", "generation": 1})
	stopClashAPI("")
	reply := apply(t, map[string]any{"mode": "local", "httpPort": port, "secret": "t", "generation": 2})
	if reply.Running {
		t.Fatalf("an apply after Close reopened the controller: %+v", reply)
	}
	if _, err := tcpGet(fmt.Sprintf("127.0.0.1:%d", port), "/version", "t"); err == nil {
		t.Fatal("something listens after Close")
	}
}

func TestApplyRacesStartAndCloseWithoutLeavingStaleListeners(t *testing.T) {
	resetRemoteControlForTest(t)
	dir, err := os.MkdirTemp("/tmp", "rr")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	socket := filepath.Join(dir, "c.sock")
	port := freePort(t)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(3)
		generation := int64(i + 1)
		go func() {
			defer wg.Done()
			recreateControlPlane(&config.Config{}, socket)
		}()
		go func() {
			defer wg.Done()
			settings, _ := json.Marshal(map[string]any{"mode": "local", "httpPort": port, "secret": fmt.Sprint(generation), "generation": generation})
			ApplyRemoteControl(string(settings))
		}()
		go func() {
			defer wg.Done()
			if generation%5 == 0 {
				stopClashAPI("")
			}
		}()
	}
	wg.Wait()
	stopClashAPI("")
	if _, err := tcpGet(fmt.Sprintf("127.0.0.1:%d", port), "/version", ""); err == nil {
		t.Fatal("a listener outlived Close")
	}
	settings, _ := json.Marshal(map[string]any{"mode": "local", "httpPort": port, "secret": "z", "generation": 99})
	ApplyRemoteControl(string(settings))
	if status := currentRemoteControlStatus(); status.Running {
		t.Fatalf("an apply after Close reports a running controller: %+v", status)
	}
	if _, err := tcpGet(fmt.Sprintf("127.0.0.1:%d", port), "/version", "z"); err == nil {
		t.Fatal("an apply after Close reopened a listener")
	}
}

func TestUnguardedNoticeFollowsTheMergedController(t *testing.T) {
	resetRemoteControlForTest(t)
	raw := &config.RawConfig{}
	raw.ExternalController = "0.0.0.0:9090"
	if len(unguardedControllerNotices(raw)) == 0 {
		t.Fatal("an unguarded configuration controller is no longer reported")
	}
	apply(t, map[string]any{"mode": "local", "httpPort": 9090, "secret": "s", "generation": 1})
	if notices := unguardedControllerNotices(raw); len(notices) != 0 {
		t.Fatalf("the App's controller replaced the configuration's, yet it is still reported: %v", notices)
	}
}

func TestANewGenerationRevokesEvenWithTheSameListeners(t *testing.T) {
	resetRemoteControlForTest(t)
	liveControlPlane(t, &config.Config{})
	port := freePort(t)
	reply := apply(t, map[string]any{"mode": "local", "httpPort": port, "secret": "s", "generation": 1})
	conn, err := net.Dial("tcp", reply.HTTP.Address)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "GET /traffic HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\nAuthorization: Bearer s\r\n\r\n",
		base64.StdEncoding.EncodeToString([]byte("0123456789abcdef")))
	reader := bufio.NewReader(conn)
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if line, err := reader.ReadString('\n'); err != nil || !strings.Contains(line, "101") {
		t.Fatalf("upgrade: %q %v", line, err)
	}
	readThroughHeadersAndOneFrame(t, reader)
	apply(t, map[string]any{"mode": "local", "httpPort": port, "secret": "s", "generation": 2})
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.Copy(io.Discard, reader); err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			t.Fatal("a stream from the previous generation kept running")
		}
	}
	if reply := apply(t, map[string]any{"mode": "local", "httpPort": port, "secret": "s", "generation": 2}); reply.HTTP.Error != "" {
		t.Fatalf("%+v", reply)
	}
}

func TestTheSameSettingRetriesAListenerThatFailed(t *testing.T) {
	resetRemoteControlForTest(t)
	liveControlPlane(t, &config.Config{})
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := occupied.Addr().(*net.TCPAddr).Port
	settings := map[string]any{"mode": "local", "httpPort": port, "secret": "s", "generation": 1}
	if reply := apply(t, settings); !strings.Contains(reply.HTTP.Error, "address already in use") {
		t.Fatalf("a held port must be reported as the bind error: %+v", reply)
	}
	_ = occupied.Close()
	if reply := apply(t, settings); reply.HTTP.Error != "" {
		t.Fatalf("the port is free now; the same setting must bind it: %+v", reply)
	}
	if code, err := tcpGet(fmt.Sprintf("127.0.0.1:%d", port), "/version", "s"); err != nil || code != http.StatusOK {
		t.Fatalf("%d %v", code, err)
	}
}

func TestALocalSettingRecordedBeforeSetupIsNotServedOnTheTelevision(t *testing.T) {
	resetRemoteControlForTest(t)
	if reply := apply(t, map[string]any{"mode": "local", "httpPort": 9090, "secret": "s", "generation": 1}); reply.Error != "" {
		t.Fatal(reply.Error)
	}
	withRuntimeProfile(t, runtimeProfileTVOSPacketTunnel)
	merged := controllerServerConfig(&config.Config{}, "")
	if merged.Addr != "" || merged.Managed {
		t.Fatalf("tvOS served a loopback controller: %+v", merged)
	}
	if status := currentRemoteControlStatus(); status.Error == "" {
		t.Fatal("the status must say the local setting is not served on tvOS")
	}
}

func TestAReloadThatRecreatesNothingStillRecordsTheConfigurationsController(t *testing.T) {
	resetRemoteControlForTest(t)
	debug := &config.Config{General: &config.General{}}
	debug.General.LogLevel = log.DEBUG
	socket := liveControlPlane(t, debug)
	before, _ := os.Stat(socket)
	previousPath := setupClashAPIPath
	setupClashAPIPath = socket
	t.Cleanup(func() { setupClashAPIPath = previousPath })

	applyExternalController(&config.Config{General: &config.General{}})
	remoteControl.mu.Lock()
	base := remoteControl.base
	remoteControl.mu.Unlock()
	if base == nil || base.IsDebug {
		t.Fatalf("a later apply would merge with the old configuration's debug switch: %+v", base)
	}
	if after, err := os.Stat(socket); err != nil || !os.SameFile(before, after) {
		t.Fatalf("a reload with nothing to re-create touched the App's socket: %v", err)
	}
}

func readThroughHeadersAndOneFrame(t *testing.T, reader *bufio.Reader) {
	t.Helper()
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("headers: %v", err)
		}
		if line == "\r\n" {
			break
		}
	}
	if _, err := reader.ReadByte(); err != nil {
		t.Fatalf("no frame arrived before the apply: %v", err)
	}
}

func TestChangingTheSecretEndsAStreamOverTheLANListenerToo(t *testing.T) {
	resetRemoteControlForTest(t)
	liveControlPlane(t, &config.Config{})
	certificate, key, _ := testCertificate(t)
	httpPort, tlsPort := freePort(t), freePort(t)
	settings := map[string]any{"mode": "lan", "httpPort": httpPort, "tlsPort": tlsPort, "secret": "old",
		"certificatePEM": certificate, "privateKeyPEM": key, "generation": 1}
	reply := apply(t, settings)
	conn, err := tls.Dial("tcp", reply.TLS.Address, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "GET /traffic HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\nAuthorization: Bearer old\r\n\r\n",
		base64.StdEncoding.EncodeToString([]byte("0123456789abcdef")))
	reader := bufio.NewReader(conn)
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if line, err := reader.ReadString('\n'); err != nil || !strings.Contains(line, "101") {
		t.Fatalf("upgrade over TLS: %q %v", line, err)
	}
	readThroughHeadersAndOneFrame(t, reader)

	settings["secret"], settings["generation"] = "new", 2
	apply(t, settings)
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.Copy(io.Discard, reader); err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			t.Fatal("a TLS stream opened with the old secret kept running")
		}
	}
}
