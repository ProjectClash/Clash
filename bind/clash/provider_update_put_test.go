package clash

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	mhttp "github.com/metacubex/http"
)

func TestUpstreamProviderUpdateChecksTheServerOnEveryListener(t *testing.T) {
	fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "rule", published: "a.example\n", served: "a.example\n", fetchedAgo: time.Second, interval: 86400})
	fixture.start()
	addr := "127.0.0.1:" + freeLoopbackPort(t)
	path := shortClashSocketPath(t)
	if err := startControlPlane(controllerConfig(t, addr), path); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stopClashAPI(path) })
	client, err := NewAPIClientWithOptions(path, newRecordingClashAPIHandler(), &APIClientOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)

	asked := fixture.requests.Load()
	fixture.serve(http.StatusOK, "a.example\nb.example\n")
	if err := client.UpdateRuleProvider("refreshed"); err != nil {
		t.Fatalf("PUT over the App's socket: %v", err)
	}
	if fixture.requests.Load() == asked || liveRuleCount() != 2 {
		t.Fatalf("the PUT did not check the server: %d requests before, %d after, %d rules running", asked, fixture.requests.Load(), liveRuleCount())
	}
	if _, entry := fixture.state(); entry == nil || entry.Result != providerRefreshUpdated {
		t.Fatalf("the check is not on record: %+v", entry)
	}

	put := func() (int, string) {
		t.Helper()
		request, _ := http.NewRequest(http.MethodPut, "http://"+addr+"/providers/rules/refreshed", nil)
		response, err := (&http.Client{Timeout: 20 * time.Second}).Do(request)
		if err != nil {
			t.Fatalf("PUT over the configuration's controller: %v", err)
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(response.Body)
		return response.StatusCode, string(body)
	}
	fixture.serve(http.StatusOK, "a.example\nb.example\nc.example\n")
	if status, body := put(); status != http.StatusNoContent || liveRuleCount() != 3 {
		t.Fatalf("an update the server answered: %d %s, %d rules running", status, body, liveRuleCount())
	}
	asked = fixture.requests.Load()
	if status, body := put(); status != http.StatusNoContent || fixture.requests.Load() == asked || liveRuleCount() != 3 {
		t.Fatalf("a check the server answered with what runs: %d %s, %d rules running", status, body, liveRuleCount())
	}
	if _, entry := fixture.state(); entry == nil || entry.Result != providerRefreshUnchanged {
		t.Fatalf("the unchanged check is not on record: %+v", entry)
	}
	fixture.serve(http.StatusInternalServerError, "")
	status, body := put()
	var answer struct {
		Message string `json:"message"`
	}
	if status != http.StatusServiceUnavailable || json.Unmarshal([]byte(body), &answer) != nil || answer.Message == "" || liveRuleCount() != 3 {
		t.Fatalf("a failed check answers upstream's 503 with the reason and keeps what runs: %d %s, %d rules running", status, body, liveRuleCount())
	}
	if _, entry := fixture.state(); entry == nil || entry.Result != providerRefreshFailed {
		t.Fatalf("the failed check is not on record: %+v", entry)
	}
}

func TestUpstreamProviderUpdateSaysWhatWaitsForTheApp(t *testing.T) {
	fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "rule", published: "a.example\n", served: "a.example\n", fetchedAgo: time.Second, interval: 86400})
	fixture.start()
	addr := "127.0.0.1:" + freeLoopbackPort(t)
	path := shortClashSocketPath(t)
	if err := startControlPlane(controllerConfig(t, addr), path); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stopClashAPI(path) })

	withBuildMemory(t, 1)
	fixture.serve(http.StatusOK, "a.example\nb.example\n")
	request, _ := http.NewRequest(http.MethodPut, "http://"+addr+"/providers/rules/refreshed", nil)
	response, err := (&http.Client{Timeout: 20 * time.Second}).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusServiceUnavailable || !strings.Contains(string(body), providerRefreshPendingMemory) || liveRuleCount() != 1 {
		t.Fatalf("content waiting for the App: %d %s, %d rules running", response.StatusCode, body, liveRuleCount())
	}
}

func TestAProviderTheRefresherDoesNotRenewDoesNotWaitForIt(t *testing.T) {
	fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "rule", published: "a.example\n", served: "a.example\n", fetchedAgo: time.Second, interval: 86400})
	fixture.start()
	hold := make(chan struct{})
	fixture.hold.Store(&hold)
	released := false
	release := func() {
		if !released {
			released = true
			close(hold)
		}
	}
	t.Cleanup(release)
	asked := fixture.requests.Load()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _, _ = requestProviderRefreshResult(context.Background(), providerRefreshRequest{kind: "rule", name: "refreshed"}, "", 10*time.Second)
	}()
	fixture.waitFor("the refresher's download to reach the server", func() bool { return fixture.requests.Load() > asked })

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	request, err := mhttp.NewRequestWithContext(ctx, mhttp.MethodPut, "http://localhost/providers/rules/local", nil)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	status, message, handled := updateProviderForUpstreamRoute(request, "rule", "local")
	if handled || time.Since(started) > time.Second {
		t.Fatalf("a provider the refresher does not renew waited %v and was answered %d %q (handled %v)", time.Since(started), status, message, handled)
	}
	release()
	<-done
}
