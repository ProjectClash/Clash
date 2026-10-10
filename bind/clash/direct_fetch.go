package clash

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ProjectClash/Clash/component/ca"
	mihomoHttp "github.com/ProjectClash/Clash/component/http"
	"github.com/ProjectClash/Clash/hub/route"
	"github.com/ProjectClash/Clash/listener/inner"
	"github.com/metacubex/chi"
	mhttp "github.com/metacubex/http"
	"github.com/metacubex/http/cookiejar"
	"golang.org/x/net/publicsuffix"
)

const DirectFetchUnavailablePrefix = "clash: direct fetch unavailable: "

const DirectFetchInterruptedPrefix = "clash: direct fetch interrupted: "

const (
	directFetchRoute = "/fetch-direct"

	directFetchAnswerHeader  = "X-Clash-Direct-Fetch"
	directFetchResultTrailer = "X-Clash-Direct-Fetch-Result"
	directFetchComplete      = "complete"

	directFetchMinimumTimeout = time.Second
	directFetchMaximumTimeout = 5 * time.Minute
	directFetchMaximumBytes   = 256 << 20
	directFetchAnswerGrace    = 5 * time.Second
	directFetchRequestBytes   = 64 << 10

	directFetchFollowAcrossOrigins = "followAcrossOrigins"
	directFetchSameOrigin          = "sameOrigin"
	directFetchDefaultRedirects    = 10
	directFetchRedirectCeiling     = 20
)

type directFetchRequest struct {
	URL                        string              `json:"url"`
	Headers                    map[string][]string `json:"headers,omitempty"`
	TimeoutMilliseconds        int64               `json:"timeoutMilliseconds"`
	MaximumBytes               int64               `json:"maximumBytes"`
	RedirectPolicy             string              `json:"redirectPolicy,omitempty"`
	MaximumRedirects           *int                `json:"maximumRedirects,omitempty"`
	AcceptAnyServerCertificate bool                `json:"acceptAnyServerCertificate,omitempty"`
}

type directFetchAnswer struct {
	Status  int                 `json:"status"`
	Headers map[string][]string `json:"headers"`
	Bytes   int64               `json:"bytes"`
}

func (r directFetchRequest) timeout() time.Duration {
	return time.Duration(r.TimeoutMilliseconds) * time.Millisecond
}

func (r directFetchRequest) validate() error {
	parsed, err := url.Parse(r.URL)
	if err != nil {
		return fmt.Errorf("clash: direct fetch %s: %w", r.URL, err)
	}
	if scheme := strings.ToLower(parsed.Scheme); (scheme != "http" && scheme != "https") || parsed.Host == "" {
		return fmt.Errorf("clash: direct fetch %s: only http and https URLs with a host can be fetched", r.URL)
	}
	if r.TimeoutMilliseconds < directFetchMinimumTimeout.Milliseconds() || r.TimeoutMilliseconds > directFetchMaximumTimeout.Milliseconds() {
		return fmt.Errorf("clash: direct fetch %s: timeoutMilliseconds %d is outside %d-%d", r.URL, r.TimeoutMilliseconds,
			directFetchMinimumTimeout.Milliseconds(), directFetchMaximumTimeout.Milliseconds())
	}
	if r.MaximumBytes < 1 || r.MaximumBytes > directFetchMaximumBytes {
		return fmt.Errorf("clash: direct fetch %s: maximumBytes %d is outside 1-%d", r.URL, r.MaximumBytes, directFetchMaximumBytes)
	}
	switch r.RedirectPolicy {
	case "", directFetchFollowAcrossOrigins, directFetchSameOrigin:
	default:
		return fmt.Errorf("clash: direct fetch %s: redirectPolicy %q is neither %s nor %s", r.URL, r.RedirectPolicy,
			directFetchFollowAcrossOrigins, directFetchSameOrigin)
	}
	if r.MaximumRedirects != nil && (*r.MaximumRedirects < 0 || *r.MaximumRedirects > directFetchRedirectCeiling) {
		return fmt.Errorf("clash: direct fetch %s: maximumRedirects %d is outside 0-%d", r.URL, *r.MaximumRedirects, directFetchRedirectCeiling)
	}
	return nil
}

func init() {
	route.Register(func(router chi.Router) {
		for _, prefix := range privateRoutePrefixes {
			router.Post(prefix+directFetchRoute, serveDirectFetch)
		}
	})
}

func serveDirectFetch(writer mhttp.ResponseWriter, request *mhttp.Request) {
	if local, ok := request.Context().Value(mhttp.LocalAddrContextKey).(net.Addr); !ok || local.Network() != "unix" {
		mhttp.NotFound(writer, request)
		return
	}
	var fetch directFetchRequest
	if err := json.NewDecoder(io.LimitReader(request.Body, directFetchRequestBytes)).Decode(&fetch); err != nil {
		mhttp.Error(writer, "clash: direct fetch: invalid request: "+err.Error(), mhttp.StatusBadRequest)
		return
	}
	if err := fetch.validate(); err != nil {
		mhttp.Error(writer, err.Error(), mhttp.StatusBadRequest)
		return
	}
	if currentCoreService() == nil {
		mhttp.Error(writer, "Clash service is not running", mhttp.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), fetch.timeout())
	defer cancel()
	response, err := directFetchGet(ctx, fetch)
	if err != nil {
		mhttp.Error(writer, directFetchFailure(ctx, err).Error(), mhttp.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	raw, body := directFetchDecoded(response)
	answer, err := json.Marshal(directFetchAnswer{Status: response.StatusCode, Headers: response.Header})
	if err != nil {
		mhttp.Error(writer, fmt.Sprintf("clash: direct fetch %s: %v", fetch.URL, err), mhttp.StatusInternalServerError)
		return
	}
	writer.Header().Set(directFetchAnswerHeader, string(answer))
	writer.Header().Set("Trailer", directFetchResultTrailer)
	writer.Header().Set("Content-Type", "application/octet-stream")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(mhttp.StatusOK)
	overLimit := fmt.Sprintf("the body is larger than maximumBytes %d", fetch.MaximumBytes)
	if response.ContentLength > fetch.MaximumBytes {
		writer.Header().Set(directFetchResultTrailer, overLimit+" (Content-Length "+fmt.Sprint(response.ContentLength)+")")
		return
	}
	copied, err := io.Copy(writer, io.LimitReader(body, fetch.MaximumBytes+1))
	result := directFetchComplete
	switch {
	case err != nil && !directFetchSucceeded(response.StatusCode):
		result = fmt.Sprintf("the body of the HTTP %d answer failed: %v", response.StatusCode, directFetchFailure(ctx, err))
	case err != nil && ctx.Err() == nil && raw.err != nil && directFetchConnectionCut(raw.err):
		result = DirectFetchInterruptedPrefix + err.Error()
	case err != nil:
		result = directFetchFailure(ctx, err).Error()
	case copied > fetch.MaximumBytes:
		result = overLimit
	}
	writer.Header().Set(directFetchResultTrailer, result)
}

func directFetchSucceeded(status int) bool {
	return status >= 200 && status <= 299
}

func directFetchConnectionCut(err error) bool {
	var operation *net.OpError
	return errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed) ||
		errors.Is(err, io.ErrClosedPipe) || errors.Is(err, syscall.ECONNRESET) || errors.As(err, &operation)
}

func directFetchGet(ctx context.Context, fetch directFetchRequest) (*mhttp.Response, error) {
	request, err := mhttp.NewRequestWithContext(ctx, mhttp.MethodGet, fetch.URL, nil)
	if err != nil {
		return nil, err
	}
	for name, values := range fetch.Headers {
		if strings.EqualFold(name, "Accept-Encoding") {
			continue
		}
		for _, value := range values {
			request.Header.Add(name, value)
		}
	}
	if request.Header.Get("User-Agent") == "" {
		request.Header.Set("User-Agent", mihomoHttp.UA())
	}
	if request.Header.Get("Range") == "" {
		request.Header.Set("Accept-Encoding", "gzip")
	}
	if user := request.URL.User; user != nil {
		password, _ := user.Password()
		request.SetBasicAuth(user.Username(), password)
	}
	tlsConfig, err := ca.GetTLSConfig(ca.Option{})
	if err != nil {
		return nil, err
	}
	tlsConfig.InsecureSkipVerify = fetch.AcceptAnyServerCertificate
	jar, err := newDirectFetchJar()
	if err != nil {
		return nil, err
	}
	client := &mhttp.Client{
		Transport: &mhttp.Transport{
			DisableKeepAlives:     true,
			DisableCompression:    true,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: time.Second,
			DialContext:           directFetchDialer{fetch: ctx}.DialContext,
			TLSClientConfig:       tlsConfig,
		},
		CheckRedirect: directFetchRedirect(fetch),
		Jar:           jar,
	}
	return client.Do(request)
}

func newDirectFetchJar() (*cookiejar.Jar, error) {
	return cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
}

func directFetchRedirect(fetch directFetchRequest) func(*mhttp.Request, []*mhttp.Request) error {
	limit := directFetchDefaultRedirects
	if fetch.MaximumRedirects != nil {
		limit = *fetch.MaximumRedirects
	}
	crossed := false
	return func(next *mhttp.Request, via []*mhttp.Request) error {
		first := via[0]
		sameOrigin := directFetchOrigin(first.URL) == directFetchOrigin(next.URL)
		next.Header.Del("Referer")
		if referer := first.Header.Get("Referer"); referer != "" && sameOrigin && !crossed {
			next.Header.Set("Referer", referer)
		}
		if fetch.RedirectPolicy == directFetchSameOrigin {
			if !sameOrigin {
				return mhttp.ErrUseLastResponse
			}
			if len(via) > directFetchRedirectCeiling {
				return fmt.Errorf("stopped after %d redirects", directFetchRedirectCeiling)
			}
			directFetchRestoreWithheld(next, via)
			return nil
		}
		if len(via) > limit {
			return mhttp.ErrUseLastResponse
		}
		if crossed || !sameOrigin {
			crossed = true
			userAgent := first.Header.Get("User-Agent")
			next.Header = mhttp.Header{}
			if userAgent != "" {
				next.Header.Set("User-Agent", userAgent)
			}
			next.Header.Set("Accept-Encoding", "gzip")
			return nil
		}
		directFetchRestoreWithheld(next, via)
		return nil
	}
}

func directFetchRestoreWithheld(next *mhttp.Request, via []*mhttp.Request) {
	first := via[0]
	withheld := next.URL.Hostname() != first.URL.Hostname()
	for _, earlier := range via[1:] {
		withheld = withheld || earlier.URL.Hostname() != first.URL.Hostname()
	}
	if !withheld {
		return
	}
	for _, name := range []string{"Authorization", "Www-Authenticate", "Cookie2"} {
		if values := first.Header.Values(name); len(values) > 0 {
			next.Header[name] = append([]string(nil), values...)
		}
	}
	superseded := map[string]bool{}
	for _, response := range []*mhttp.Response{next.Response} {
		if response != nil {
			for _, cookie := range response.Cookies() {
				superseded[cookie.Name] = true
			}
		}
	}
	for _, earlier := range via[1:] {
		if earlier.Response != nil {
			for _, cookie := range earlier.Response.Cookies() {
				superseded[cookie.Name] = true
			}
		}
	}
	var kept []string
	for _, cookie := range first.Cookies() {
		if !superseded[cookie.Name] {
			kept = append(kept, cookie.Name+"="+cookie.Value)
		}
	}
	next.Header.Del("Cookie")
	if len(kept) > 0 {
		next.Header.Set("Cookie", strings.Join(kept, "; "))
	}
}

func directFetchDecoded(response *mhttp.Response) (*directFetchBodyReader, io.Reader) {
	raw := &directFetchBodyReader{reader: response.Body}
	asked := response.Request != nil && response.Request.Header.Get("Accept-Encoding") == "gzip"
	if !asked || response.ContentLength == 0 || !strings.EqualFold(response.Header.Get("Content-Encoding"), "gzip") {
		return raw, raw
	}
	response.Header.Del("Content-Encoding")
	response.Header.Del("Content-Length")
	response.ContentLength = -1
	response.Uncompressed = true
	return raw, &directFetchGzipReader{source: raw}
}

type directFetchGzipReader struct {
	source io.Reader
	reader *gzip.Reader
	err    error
}

func (g *directFetchGzipReader) Read(p []byte) (int, error) {
	if g.err != nil {
		return 0, g.err
	}
	if g.reader == nil {
		g.reader, g.err = gzip.NewReader(g.source)
		if g.err != nil {
			return 0, g.err
		}
	}
	return g.reader.Read(p)
}

func directFetchOrigin(u *url.URL) string {
	port := u.Port()
	if number, err := strconv.Atoi(port); err == nil {
		port = strconv.Itoa(number)
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Hostname()) + ":" + port
}

func directFetchFailure(ctx context.Context, err error) error {
	if cause := ctx.Err(); cause != nil && !errors.Is(err, cause) {
		return fmt.Errorf("%w: %w", cause, err)
	}
	return err
}

type directFetchDialer struct {
	fetch context.Context
}

func (d directFetchDialer) DialContext(_ context.Context, _, address string) (net.Conn, error) {
	return inner.HandleTcpContext(d.fetch, inner.GetTunnel(), address, "DIRECT")
}

func (directFetchDialer) ListenPacket(context.Context, string, string, netip.AddrPort) (net.PacketConn, error) {
	return nil, errors.New("clash: direct fetch dials TCP only")
}

func (c *APIClient) FetchDirect(requestJSON string, destinationPath string) (string, error) {
	answer, err := recoverAppCall("FetchDirect", func() (string, error) {
		return c.fetchDirect(requestJSON, destinationPath)
	})
	return bridgeSafeString(answer), bridgeSafeError(err)
}

func (c *APIClient) fetchDirect(requestJSON, destinationPath string) (string, error) {
	var fetch directFetchRequest
	if err := json.Unmarshal([]byte(requestJSON), &fetch); err != nil {
		return "", fmt.Errorf("clash: direct fetch: invalid request: %w", err)
	}
	if err := fetch.validate(); err != nil {
		return "", err
	}
	if destinationPath == "" {
		return "", fmt.Errorf("clash: direct fetch %s: no destination path", fetch.URL)
	}
	payload, err := json.Marshal(fetch)
	if err != nil {
		return "", fmt.Errorf("clash: direct fetch %s: %w", fetch.URL, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), fetch.timeout()+directFetchAnswerGrace)
	defer cancel()
	path := c.privatePath(directFetchRoute)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://localhost"+path, strings.NewReader(string(payload)))
	if err != nil {
		return "", fmt.Errorf("clash: direct fetch %s: %w", fetch.URL, err)
	}
	request.Host = "localhost"
	request.Header.Set("Content-Type", "application/json")
	response, err := c.httpClient.Do(request)
	if err != nil {
		var dial *net.OpError
		switch {
		case errors.As(err, &dial) && dial.Op == "dial":
			return "", fmt.Errorf("%sthe Extension is not answering on %s: %w", DirectFetchUnavailablePrefix, c.socketPath, err)
		case ctx.Err() != nil:
			return "", fmt.Errorf("clash: direct fetch %s: the Extension did not answer: %w", fetch.URL, err)
		default:
			return "", fmt.Errorf("%s%s: the Extension did not answer: %w", DirectFetchInterruptedPrefix, fetch.URL, err)
		}
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		refusal, _ := io.ReadAll(io.LimitReader(response.Body, clashAPIMaxMessageSize))
		text := strings.TrimSpace(string(refusal))
		if response.StatusCode == http.StatusNotFound || response.StatusCode == http.StatusServiceUnavailable {
			return "", fmt.Errorf("%sHTTP %d from %s: %s", DirectFetchUnavailablePrefix, response.StatusCode, path, text)
		}
		if response.StatusCode == http.StatusBadGateway {
			return "", fmt.Errorf("clash: direct fetch: %s", text)
		}
		return "", fmt.Errorf("clash: direct fetch %s: HTTP %d from the Extension: %s", fetch.URL, response.StatusCode, text)
	}
	var answer directFetchAnswer
	if err := json.Unmarshal([]byte(response.Header.Get(directFetchAnswerHeader)), &answer); err != nil {
		return "", fmt.Errorf("clash: direct fetch %s: the Extension's answer has no readable origin status: %w", fetch.URL, err)
	}
	if answer.Headers == nil {
		answer.Headers = map[string][]string{}
	}
	staging, err := os.CreateTemp(filepath.Dir(destinationPath), directFetchStagingPattern)
	if err != nil {
		return "", fmt.Errorf("clash: direct fetch %s: %w", fetch.URL, err)
	}
	encoded, err := finishDirectFetch(ctx, response, staging, &answer, fetch.MaximumBytes, destinationPath)
	if err != nil && !directFetchSucceeded(answer.Status) && !strings.Contains(err.Error(), fmt.Sprintf("HTTP %d", answer.Status)) {
		err = fmt.Errorf("the HTTP %d answer: %w", answer.Status, err)
	}
	if err != nil {
		if removeErr := os.Remove(staging.Name()); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			err = fmt.Errorf("%w (and %s could not be removed: %v)", err, staging.Name(), removeErr)
		}
		if errors.As(err, new(directFetchInterruption)) {
			return "", fmt.Errorf("%s%s: %w", DirectFetchInterruptedPrefix, fetch.URL, err)
		}
		return "", fmt.Errorf("clash: direct fetch %s: %w", fetch.URL, err)
	}
	return encoded, nil
}

type directFetchBodyReader struct {
	reader io.Reader
	err    error
}

func (r *directFetchBodyReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if err != nil && err != io.EOF {
		r.err = err
	}
	return n, err
}

type directFetchInterruption struct {
	err error
}

func (i directFetchInterruption) Error() string { return i.err.Error() }
func (i directFetchInterruption) Unwrap() error { return i.err }

const directFetchStagingPattern = ".direct-fetch-*"

func finishDirectFetch(ctx context.Context, response *http.Response, staging *os.File, answer *directFetchAnswer, maximumBytes int64, destination string) (string, error) {
	written, err := writeDirectFetchBody(ctx, response, staging, maximumBytes, answer.Status)
	if err != nil {
		return "", err
	}
	answer.Bytes = written
	encoded, err := json.Marshal(answer)
	if err != nil {
		return "", err
	}
	if err := os.Rename(staging.Name(), destination); err != nil {
		return "", err
	}
	return string(encoded), nil
}

func writeDirectFetchBody(ctx context.Context, response *http.Response, file *os.File, maximumBytes int64, status int) (int64, error) {
	body := &directFetchBodyReader{reader: response.Body}
	written, copyErr := io.Copy(file, io.LimitReader(body, maximumBytes+1))
	closeErr := file.Close()
	switch {
	case copyErr != nil && body.err != nil && errors.Is(copyErr, body.err) && ctx.Err() == nil:
		if !directFetchSucceeded(status) {
			return written, fmt.Errorf("the body of the HTTP %d answer was cut off on the way from the Extension: %w", status, copyErr)
		}
		return written, directFetchInterruption{copyErr}
	case copyErr != nil:
		return written, copyErr
	case closeErr != nil:
		return written, closeErr
	}
	if written > maximumBytes {
		return written, fmt.Errorf("the body is larger than maximumBytes %d", maximumBytes)
	}
	switch result := response.Trailer.Get(directFetchResultTrailer); {
	case result == directFetchComplete:
		return written, nil
	case result == "" && !directFetchSucceeded(status):
		return written, fmt.Errorf("the HTTP %d answer ended without the core's last word", status)
	case result == "":
		return written, directFetchInterruption{errors.New("the Extension's answer ended before the core said the download finished")}
	case strings.HasPrefix(result, DirectFetchInterruptedPrefix) && !directFetchSucceeded(status):
		return written, fmt.Errorf("the body of the HTTP %d answer failed: %s", status, strings.TrimPrefix(result, DirectFetchInterruptedPrefix))
	case strings.HasPrefix(result, DirectFetchInterruptedPrefix):
		return written, directFetchInterruption{errors.New(strings.TrimPrefix(result, DirectFetchInterruptedPrefix))}
	default:
		return written, errors.New(result)
	}
}
