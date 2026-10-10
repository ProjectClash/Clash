package clash

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ProjectClash/Clash/hub/route"
	"github.com/metacubex/chi"
	mhttp "github.com/metacubex/http"
)

const (
	providerUpdateRoute        = "/provider-update"
	providerSeedRoute          = "/provider-seed"
	providerUpdateRequestBytes = 4 << 10
)

func init() {
	route.Register(func(router chi.Router) {
		for _, prefix := range privateRoutePrefixes {
			router.Post(prefix+providerUpdateRoute, serveProviderUpdate)
			router.Post(prefix+providerSeedRoute, serveProviderSeed)
		}
	})
}

type providerUpdateRequest struct {
	Kind                string `json:"kind"`
	Name                string `json:"name"`
	TimeoutMilliseconds int32  `json:"timeoutMilliseconds"`
}

func appGroupSocketOnly(handler mhttp.HandlerFunc) mhttp.HandlerFunc {
	return func(writer mhttp.ResponseWriter, request *mhttp.Request) {
		if !overAppGroupSocket(request) {
			mhttp.Error(writer, "this route answers only the App's own socket", mhttp.StatusForbidden)
			return
		}
		handler(writer, request)
	}
}

func overAppGroupSocket(request *mhttp.Request) bool {
	local, ok := request.Context().Value(mhttp.LocalAddrContextKey).(net.Addr)
	return ok && local.Network() == "unix"
}

func providerRequestTimeout(milliseconds int32) time.Duration {
	if milliseconds <= 0 {
		return 60 * time.Second
	}
	if milliseconds > 300000 {
		milliseconds = 300000
	}
	return time.Duration(milliseconds) * time.Millisecond
}

func serveProviderUpdate(writer mhttp.ResponseWriter, request *mhttp.Request) {
	if !overAppGroupSocket(request) && !route.RequestFromManagedListener(request) {
		mhttp.NotFound(writer, request)
		return
	}
	var update providerUpdateRequest
	if err := json.NewDecoder(io.LimitReader(request.Body, providerUpdateRequestBytes)).Decode(&update); err != nil ||
		(update.Kind != "rule" && update.Kind != "proxy") || !validProviderSideUpdateName(update.Name) {
		mhttp.Error(writer, "invalid provider selector", mhttp.StatusBadRequest)
		return
	}
	answerProviderRefresh(writer, request.Context(), providerRefreshRequest{kind: update.Kind, name: update.Name}, "", providerRequestTimeout(update.TimeoutMilliseconds))
}

func serveProviderSeed(writer mhttp.ResponseWriter, request *mhttp.Request) {
	if !overAppGroupSocket(request) {
		mhttp.NotFound(writer, request)
		return
	}
	query := request.URL.Query()
	kind, name, expected := query.Get("kind"), query.Get("name"), query.Get("expect")
	if (kind != "proxy" && kind != "rule") || !validProviderSideUpdateName(name) || !validConfigurationSHA256(expected, true) {
		mhttp.Error(writer, "invalid provider selector", mhttp.StatusBadRequest)
		return
	}
	var seed providerSeed
	if err := json.Unmarshal([]byte(query.Get("seed")), &seed); err != nil {
		mhttp.Error(writer, "invalid seed description", mhttp.StatusBadRequest)
		return
	}
	if currentCoreService() == nil || providerCache.homeDirectory() == "" {
		mhttp.Error(writer, ProviderUpdateUnavailablePrefix+"no tunnel is running", mhttp.StatusServiceUnavailable)
		return
	}
	path, size, err := streamSeedBody(request.Body)
	if err != nil {
		mhttp.Error(writer, "invalid provider payload: "+err.Error(), mhttp.StatusBadRequest)
		return
	}
	seed.path, seed.bytes = path, size
	answerProviderRefresh(writer, request.Context(), providerRefreshRequest{kind: kind, name: name, seed: &seed}, expected, 60*time.Second)
}

const providerRefreshIncomingDirectory = "incoming"

func streamSeedBody(body io.Reader) (string, int64, error) {
	directory := filepath.Join(providerCache.rootDirectory(), providerRefreshIncomingDirectory)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", 0, err
	}
	file, err := os.CreateTemp(directory, "seed-")
	if err != nil {
		return "", 0, err
	}
	written, err := io.Copy(file, io.LimitReader(body, int64(maximumProviderResourceBytes)+1))
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err == nil && (written == 0 || written > int64(maximumProviderResourceBytes)) {
		err = fmt.Errorf("its size %d is not within 1..%d bytes", written, maximumProviderResourceBytes)
	}
	if err != nil {
		_ = os.Remove(file.Name())
		return "", 0, err
	}
	return file.Name(), written, nil
}

func removeStaleRefreshFiles() {
	cutoff := time.Now().Add(-10 * time.Minute)
	root := providerCache.rootDirectory()
	remove := func(directory, prefix string) {
		names, err := os.ReadDir(directory)
		if err != nil {
			return
		}
		for _, name := range names {
			if !strings.HasPrefix(name.Name(), prefix) {
				continue
			}
			if info, err := name.Info(); err == nil && info.Mode().IsRegular() && info.ModTime().Before(cutoff) {
				_ = os.Remove(filepath.Join(directory, name.Name()))
			}
		}
	}
	remove(filepath.Join(root, providerRefreshIncomingDirectory), "seed-")
	cache := filepath.Join(root, providerRefreshCacheDirectory)
	_ = filepath.WalkDir(cache, func(path string, entry os.DirEntry, err error) error {
		if err != nil || !entry.Type().IsRegular() {
			return nil
		}
		name := entry.Name()
		if strings.HasPrefix(name, ".download-") || strings.Contains(name, ".link-") || strings.HasSuffix(name, ".rollback") {
			if info, err := entry.Info(); err == nil && info.ModTime().Before(cutoff) {
				_ = os.Remove(path)
			}
		}
		return nil
	})
}

func answerProviderRefresh(writer mhttp.ResponseWriter, parent context.Context, refresh providerRefreshRequest, expected string, timeout time.Duration) {
	answer, status, message := requestProviderRefresh(parent, refresh, expected, timeout)
	if status != mhttp.StatusOK {
		mhttp.Error(writer, message, status)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(mhttp.StatusOK)
	_, _ = writer.Write(answer)
}

func requestProviderRefresh(parent context.Context, refresh providerRefreshRequest, expected string, timeout time.Duration) ([]byte, int, string) {
	delivered := false
	defer func() {
		if !delivered && refresh.seed != nil && refresh.seed.path != "" {
			_ = os.Remove(refresh.seed.path)
		}
	}()
	service := currentCoreService()
	if service == nil {
		return nil, mhttp.StatusServiceUnavailable, ProviderUpdateUnavailablePrefix + "no tunnel is running"
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	type serviceSnapshot struct {
		refresher *providerRefresher
		running   string
	}
	snapshots := make(chan serviceSnapshot, 1)
	go func() {
		service.mu.Lock()
		snapshot := serviceSnapshot{service.refresher, service.runningConfigSHA256}
		service.mu.Unlock()
		snapshots <- snapshot
	}()
	var snapshot serviceSnapshot
	select {
	case snapshot = <-snapshots:
	case <-ctx.Done():
		return nil, mhttp.StatusGatewayTimeout, "clash: provider update: the tunnel is busy with its configuration"
	}
	refresher, running := snapshot.refresher, snapshot.running
	if expected != "" && expected != running {
		return nil, mhttp.StatusConflict, SideUpdateStalePrefix + "the running configuration is not the one this seed was prepared for"
	}
	if refresher == nil {
		return nil, mhttp.StatusServiceUnavailable, ProviderUpdateUnavailablePrefix + "no tunnel is running"
	}
	refresh.reply = make(chan providerRefreshResult, 1)
	select {
	case refresher.requests <- refresh:
		delivered = true
	case <-refresher.ctx.Done():
		return nil, mhttp.StatusServiceUnavailable, ProviderUpdateUnavailablePrefix + "the tunnel's configuration changed"
	case <-ctx.Done():
		return nil, mhttp.StatusGatewayTimeout, "clash: provider update: the tunnel is busy with another provider"
	}
	var result providerRefreshResult
	select {
	case result = <-refresh.reply:
	case <-ctx.Done():
		return nil, mhttp.StatusGatewayTimeout, "clash: provider update: still running in the tunnel; its result will be in the state file"
	}
	if result.stale {
		return nil, mhttp.StatusServiceUnavailable, ProviderUpdateUnavailablePrefix + "the tunnel's configuration changed"
	}
	if strings.HasPrefix(result.Error, ProviderUpdateUnavailablePrefix) {
		return nil, mhttp.StatusNotFound, result.Error
	}
	answer, err := json.Marshal(result)
	if err != nil {
		return nil, mhttp.StatusInternalServerError, err.Error()
	}
	return answer, mhttp.StatusOK, ""
}

func UpdateProviderJSON(kind, name string, timeoutMilliseconds int32) string {
	if (kind != "rule" && kind != "proxy") || !validProviderSideUpdateName(name) {
		return bridgeSafeString(dnsQueryError("invalid provider selector"))
	}
	answer, status, message := requestProviderRefresh(context.Background(),
		providerRefreshRequest{kind: kind, name: name}, "", providerRequestTimeout(timeoutMilliseconds))
	if status != mhttp.StatusOK {
		return bridgeSafeString(dnsQueryError(message))
	}
	return bridgeSafeString(string(answer))
}

func SeedProviderFileJSON(kind, name, payloadPath, seedJSON, expectedConfigSHA256 string) string {
	if (kind != "rule" && kind != "proxy") || !validProviderSideUpdateName(name) || !validConfigurationSHA256(expectedConfigSHA256, true) {
		return bridgeSafeString(dnsQueryError("invalid provider selector"))
	}
	var seed providerSeed
	if err := json.Unmarshal([]byte(seedJSON), &seed); err != nil {
		return bridgeSafeString(dnsQueryError("invalid seed description"))
	}
	home := providerCache.homeDirectory()
	if currentCoreService() == nil || home == "" {
		return bridgeSafeString(dnsQueryError(ProviderUpdateUnavailablePrefix + "no tunnel is running"))
	}
	if !providerSourceContained(payloadPath, home) {
		return bridgeSafeString(dnsQueryError("invalid provider payload: the file is not under the tunnel's home"))
	}
	file, err := os.Open(payloadPath)
	if err != nil {
		return bridgeSafeString(dnsQueryError("invalid provider payload: " + err.Error()))
	}
	path, size, err := streamSeedBody(file)
	_ = file.Close()
	if err != nil {
		return bridgeSafeString(dnsQueryError("invalid provider payload: " + err.Error()))
	}
	seed.path, seed.bytes = path, size
	answer, status, message := requestProviderRefresh(context.Background(),
		providerRefreshRequest{kind: kind, name: name, seed: &seed}, expectedConfigSHA256, 60*time.Second)
	if status != mhttp.StatusOK {
		return bridgeSafeString(dnsQueryError(message))
	}
	return bridgeSafeString(string(answer))
}

func (c *APIClient) UpdateProvider(kind, name string, timeoutMilliseconds int32) (string, error) {
	body, err := json.Marshal(providerUpdateRequest{Kind: kind, Name: name, TimeoutMilliseconds: timeoutMilliseconds})
	if err != nil {
		return "", bridgeSafeError(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), providerRequestTimeout(timeoutMilliseconds)+5*time.Second)
	defer cancel()
	answer, err := c.providerRefreshCall(ctx, providerUpdateRoute, body)
	return bridgeSafeString(answer), bridgeSafeError(err)
}

func (c *APIClient) SeedProvider(kind, name string, payload []byte, seedJSON, expectedConfigSHA256 string) (string, error) {
	if !validProviderSideUpdateName(name) || (kind != "rule" && kind != "proxy") {
		return "", bridgeSafeError(errors.New("clash: seed requires a valid provider kind and name"))
	}
	if len(payload) == 0 || len(payload) > maximumProviderResourceBytes {
		return "", bridgeSafeError(errors.New("clash: seed payload size is invalid"))
	}
	query := url.Values{"kind": []string{kind}, "name": []string{name}, "seed": []string{seedJSON}}
	if expectedConfigSHA256 != "" {
		query.Set("expect", expectedConfigSHA256)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 65*time.Second)
	defer cancel()
	answer, err := c.providerRefreshCall(ctx, providerSeedRoute+"?"+query.Encode(), payload)
	return bridgeSafeString(answer), bridgeSafeError(err)
}

func (c *APIClient) providerRefreshCall(ctx context.Context, suffix string, payload []byte) (string, error) {
	endpoint, status, body, err := c.privateBinaryStatus(ctx, mhttp.MethodPost, suffix, payload)
	if err != nil {
		return "", err
	}
	if status == mhttp.StatusOK {
		return body, nil
	}
	message := strings.TrimSpace(body)
	if strings.HasPrefix(message, ProviderUpdateUnavailablePrefix) || strings.HasPrefix(message, SideUpdateStalePrefix) {
		return "", errors.New(message)
	}
	if status == mhttp.StatusNotFound {
		return "", errors.New(ProviderUpdateUnavailablePrefix + "this core does not refresh providers")
	}
	return "", fmt.Errorf("clash: %s answered %d: %s", endpoint, status, message)
}
