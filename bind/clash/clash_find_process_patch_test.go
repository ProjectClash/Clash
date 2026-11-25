package clash

import (
	"errors"
	"net/http"
	"testing"

	"github.com/ProjectClash/Clash/component/process"
	"github.com/ProjectClash/Clash/tunnel"
)

func TestAPatchedFindProcessModeFindsNothingWithoutScanningOnIOS(t *testing.T) {
	withRuntimeProfile(t, currentRuntimeProfile())
	priorMode := tunnel.FindProcessMode()
	t.Cleanup(func() { tunnel.SetFindProcessMode(priorMode) })

	options := testOptions(t)
	options.RuntimeProfile = RuntimeProfileIOSPacketTunnel
	if err := Setup(options); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	service, err := NewService(newRecordingPlatform())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	t.Cleanup(func() { _ = service.Close() })
	if err := service.Start(helloYAML); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if mode := tunnel.FindProcessMode(); mode != process.FindProcessOff {
		t.Fatalf("parsed find-process-mode = %v, want off on iOS", mode)
	}
	path := shortClashSocketPath(t)
	if err := startControlPlane(nil, path); err != nil {
		t.Fatalf("startControlPlane: %v", err)
	}
	t.Cleanup(func() { stopClashAPI(path) })
	client, err := NewAPIClient(path, newRecordingClashAPIHandler())
	if err != nil {
		t.Fatalf("NewAPIClient: %v", err)
	}
	t.Cleanup(client.Close)

	if _, err := client.request(http.MethodPatch, "/configs", map[string]string{"find-process-mode": "strict"}); err != nil {
		t.Fatalf("PATCH /configs find-process-mode: %v", err)
	}
	if mode := tunnel.FindProcessMode(); mode != process.FindProcessStrict {
		t.Fatalf("find-process-mode after PATCH = %v, want strict, as upstream takes it", mode)
	}
	_, owner, err := process.FindConnectionOwner(process.TCP, ownerSource, 52000, ownerDestination, 443)
	if owner != "" || !errors.Is(err, process.ErrOwnerResolverIsFinal) {
		t.Fatalf("owner=%q err=%v, want no owner and a final failure (no table read)", owner, err)
	}
}
