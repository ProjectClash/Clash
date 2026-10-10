package clash

import (
	"os"
	"testing"
	"time"
)

func TestConfigurationsThisTreeAcceptsActuallyStart(t *testing.T) {
	setupConfigPipelineTest(t)

	base := "proxies:\n  - {name: N, type: ss, server: 127.0.0.1, port: 8388, cipher: aes-128-gcm, password: p}\n" +
		"proxy-groups:\n  - {name: G, type: select, proxies: [N, DIRECT]}\nrules:\n  - MATCH,G\n"

	for name, document := range map[string]string{
		"plain":                         base,
		"http provider with no url":     base + "rule-providers:\n  r: {type: http, behavior: domain, format: yaml, path: ./r.yaml}\n",
		"file provider that is missing": base + "proxy-providers:\n  p: {type: file, path: ./no-such-provider.yaml}\n",
		"health-check timeout is negative": base + "proxy-providers:\n  p:\n    type: inline\n    payload:\n" +
			"      - {name: M, type: ss, server: 127.0.0.1, port: 8388, cipher: aes-128-gcm, password: p}\n" +
			"    health-check: {enable: true, url: 'http://e.com', timeout: -1}\n",
	} {
		t.Run(name, func(t *testing.T) {
			service, err := NewService(newRecordingPlatform())
			if err != nil {
				t.Fatalf("NewService: %v", err)
			}
			defer func() { _ = service.Close() }()

			done := make(chan error, 1)
			begin := time.Now()
			go func() { done <- service.Start(document) }()
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("this tree accepts this configuration everywhere else and Start refuses it "+
						"after %v: %v", time.Since(begin).Round(time.Millisecond), err)
				}
			case <-time.After(45 * time.Second):
				t.Fatalf("Start never returned; a hang is not a refusal and leaves no error to read")
			}
		})
	}
}

func TestAConfigurationTheKernelMustRefuseComesBackAsAnError(t *testing.T) {
	setupConfigPipelineTest(t)
	service, err := NewService(newRecordingPlatform())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	defer func() { _ = service.Close() }()

	done := make(chan error, 1)
	go func() { done <- service.Start("proxies:\n  - {name: [unclosed\n") }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Start accepted a document that is not yaml")
		}
		if !containsAll(err.Error(), "parse config", "did not find expected") {
			t.Fatalf("the refusal does not carry mihomo's own words: %v", err)
		}
	case <-time.After(45 * time.Second):
		t.Fatal("Start never returned on a document that cannot parse")
	}
	_ = os.Getenv
}

func containsAll(haystack string, needles ...string) bool {
	for _, needle := range needles {
		found := false
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
