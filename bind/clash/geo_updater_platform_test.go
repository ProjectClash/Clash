package clash

import (
	"net/http"
	"testing"
	"time"
)

func TestGeoUpdaterRoutesFollowThePlatformThatCanAffordThem(t *testing.T) {
	for _, testCase := range []struct {
		profile runtimeProfile
		open    bool
		why     string
	}{
		{runtimeProfileIOSPacketTunnel, false, "17 MB fetched and unpacked inside an extension measured dying at 49.5 MiB"},
		{runtimeProfileMacOSPacketTunnel, true, "a macOS app extension was measured living at 62.4 MiB with no limit configured"},
		{runtimeProfileMacOSApplication, true, "the containing app has no extension budget at all"},
	} {
		t.Run(testCase.profile.String(), func(t *testing.T) {
			withRuntimeProfile(t, testCase.profile)

			port := freeLoopbackPort(t)
			addr := "127.0.0.1:" + port
			path := shortClashSocketPath(t)
			cfg := controllerConfig(t, addr)
			if err := startControlPlane(cfg, path); err != nil {
				t.Fatalf("startControlPlane: %v", err)
			}
			t.Cleanup(func() { stopClashAPI(path) })

			client := &http.Client{Timeout: 3 * time.Second}
			for _, route := range []string{"/configs/geo", "/upgrade/geo"} {
				response, err := client.Get("http://" + addr + route)
				if err != nil {
					t.Fatalf("GET %s: %v", route, err)
				}
				_ = response.Body.Close()
				registered := response.StatusCode == http.StatusMethodNotAllowed
				if registered != testCase.open {
					t.Errorf("%s registered=%v on %s, want %v: %s",
						route, registered, testCase.profile, testCase.open, testCase.why)
				}
			}

			response, err := client.Get("http://" + addr + "/configs")
			if err != nil || response.StatusCode != http.StatusOK {
				t.Fatalf("GET /configs = %v/%v; nothing above was measured", err, response)
			}
			_ = response.Body.Close()
		})
	}
}
