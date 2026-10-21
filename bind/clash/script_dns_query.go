package clash

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	"mime"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ProjectClash/Clash/component/resolver"
	"github.com/ProjectClash/Clash/dns"
	"github.com/ProjectClash/Clash/hub/route"
	"github.com/ProjectClash/Clash/log"
	"github.com/ProjectClash/Clash/tunnel"
	"github.com/metacubex/chi"
	"github.com/metacubex/http"

	D "github.com/miekg/dns"
	"github.com/samber/lo"
)

const (
	scriptDNSDefaultTimeout = 3 * time.Second
	scriptDNSLongestCall    = 30 * time.Second
	scriptDNSRoundsAtOnce   = 8
	scriptDNSRequestLimit   = 4096
)

var scriptDNSSlots = &lazyValue[chan struct{}]{build: func() chan struct{} {
	return make(chan struct{}, scriptDNSRoundsAtOnce)
}}

func init() {
	route.Register(func(router chi.Router) {
		for _, prefix := range privateRoutePrefixes {
			router.Post(prefix+"/dns/script-query", serveScriptDNSQuery)
		}
	})
}

func ScriptDNSQueryJSON(requestJSON string) string {
	return bridgeSafeString(scriptDNSQuery(context.Background(), []byte(requestJSON)))
}

func serveScriptDNSQuery(writer http.ResponseWriter, request *http.Request) {
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		http.Error(writer, "content type must be application/json", http.StatusUnsupportedMediaType)
		return
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, scriptDNSRequestLimit+1))
	if err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}
	if len(body) > scriptDNSRequestLimit {
		http.Error(writer, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	_, _ = io.WriteString(writer, scriptDNSQuery(request.Context(), body))
}

type scriptDNSError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type scriptDNSRecord struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
	TTL   uint32 `json:"ttl"`
}

type scriptDNSAnswer struct {
	Domain    string            `json:"domain"`
	Protocol  string            `json:"protocol"`
	Server    string            `json:"server"`
	FromCache bool              `json:"fromCache"`
	Answers   []scriptDNSRecord `json:"answers"`
}

type scriptDNSRequest struct {
	domain   string
	protocol string
	server   dns.NameServer
	shown    string
	types    []uint16
	timeout  time.Duration
}

func scriptDNSQuery(parent context.Context, body []byte) string {
	started := time.Now()
	request, failure := parseScriptDNSRequest(body)
	var answer *scriptDNSAnswer
	if failure == nil {
		ctx, cancel := context.WithTimeout(parent, scriptDNSLongestCall)
		answer, failure = request.ask(ctx)
		cancel()
	}
	request.log(time.Since(started), answer, failure)
	var encoded []byte
	var err error
	if failure != nil {
		encoded, err = json.Marshal(map[string]*scriptDNSError{"error": failure})
	} else {
		encoded, err = json.Marshal(answer)
	}
	if err != nil {
		return `{"error":{"code":"QUERY_FAILED","message":"the answer could not be encoded"}}`
	}
	return string(encoded)
}

func parseScriptDNSRequest(body []byte) (*scriptDNSRequest, *scriptDNSError) {
	request := &scriptDNSRequest{timeout: scriptDNSDefaultTimeout}
	var wire struct {
		Domain              string   `json:"domain"`
		Protocol            string   `json:"protocol"`
		Server              string   `json:"server"`
		Types               []string `json:"types"`
		TimeoutMilliseconds *int64   `json:"timeoutMilliseconds"`
	}
	if err := json.Unmarshal(body, &wire); err != nil {
		return request, &scriptDNSError{"INVALID_ARGUMENT", "the request is not JSON of the documented shape: " + err.Error()}
	}
	request.domain = strings.TrimSpace(wire.Domain)
	request.protocol = strings.ToLower(strings.TrimSpace(wire.Protocol))
	if request.domain == "" {
		return request, &scriptDNSError{"INVALID_ARGUMENT", "a query needs a domain"}
	}
	if _, ok := D.IsDomainName(request.domain); !ok {
		return request, &scriptDNSError{"INVALID_ARGUMENT", fmt.Sprintf("%q is not a domain name", request.domain)}
	}
	if wire.TimeoutMilliseconds != nil {
		milliseconds := *wire.TimeoutMilliseconds
		if milliseconds <= 0 {
			return request, &scriptDNSError{"INVALID_ARGUMENT", fmt.Sprintf("timeoutMilliseconds must be more than 0, got %d", milliseconds)}
		}
		request.timeout = time.Duration(min(milliseconds, scriptDNSLongestCall.Milliseconds())) * time.Millisecond
	}
	names := wire.Types
	if len(names) == 0 {
		names = []string{"A", "AAAA"}
	}
	for _, name := range names {
		queryType, ok := D.StringToType[strings.ToUpper(strings.TrimSpace(name))]
		if !ok {
			return request, &scriptDNSError{"INVALID_ARGUMENT", "invalid query type: " + name}
		}
		if !lo.Contains(request.types, queryType) {
			request.types = append(request.types, queryType)
		}
	}
	server, protocol, refusal := scriptDNSServer(wire.Protocol, wire.Server)
	request.protocol = protocol
	if refusal != nil {
		if request.protocol == "" {
			request.protocol = strings.ToLower(strings.TrimSpace(wire.Protocol))
		}
		request.shown = strings.TrimSpace(wire.Server)
		return request, refusal
	}
	request.server, request.shown = server, scriptDNSServerShown(protocol, server)
	return request, nil
}

func scriptDNSServer(protocol, server string) (dns.NameServer, string, *scriptDNSError) {
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	server = strings.TrimSpace(server)
	scheme := ""
	if at := strings.Index(server, "://"); at >= 0 {
		scheme = strings.ToLower(server[:at])
	}
	if protocol == "" {
		switch {
		case server == "" || strings.EqualFold(server, "system"):
			protocol = "auto"
		case scheme == "" || scheme == "udp":
			protocol = "udp"
		case scheme == "https" || scheme == "http":
			protocol = "doh"
		case scheme == "h3":
			protocol = "doh3"
		case scheme == "quic":
			protocol = "quic"
		default:
			return dns.NameServer{}, "", &scriptDNSError{"UNSUPPORTED_PROTOCOL", fmt.Sprintf("%s:// servers are not asked here: udp, doh, doh3 and quic are", scheme)}
		}
	}
	text := server
	switch protocol {
	case "auto":
		return dns.NameServer{}, protocol, nil
	case "udp":
		if scheme != "" && scheme != "udp" {
			return dns.NameServer{}, protocol, &scriptDNSError{"INVALID_SERVER", fmt.Sprintf("%q is not a UDP server", server)}
		}
	case "doh":
		if scheme != "https" && scheme != "http" {
			return dns.NameServer{}, protocol, &scriptDNSError{"INVALID_SERVER", fmt.Sprintf("%q is not a DoH URL (https://)", server)}
		}
	case "doh3":
		switch scheme {
		case "h3":
			text = "https" + server[len("h3"):]
		case "https":
		default:
			return dns.NameServer{}, protocol, &scriptDNSError{"INVALID_SERVER", fmt.Sprintf("%q is not a DoH3 URL (h3:// or https://)", server)}
		}
	case "quic":
		switch scheme {
		case "":
			text = "quic://" + server
		case "quic":
		default:
			return dns.NameServer{}, protocol, &scriptDNSError{"INVALID_SERVER", fmt.Sprintf("%q is not a DoQ server (quic://)", server)}
		}
	default:
		return dns.NameServer{}, protocol, &scriptDNSError{"UNSUPPORTED_PROTOCOL", fmt.Sprintf("%q is not a protocol here: auto, udp, doh, doh3 and quic are", protocol)}
	}
	if server == "" {
		return dns.NameServer{}, protocol, &scriptDNSError{"INVALID_SERVER", "a " + protocol + " query names its server"}
	}
	if dns.ParseNameServer == nil {
		return dns.NameServer{}, protocol, &scriptDNSError{"UNAVAILABLE", "this core cannot read a name server"}
	}
	servers, err := dns.ParseNameServer([]string{text})
	if err != nil {
		return dns.NameServer{}, protocol, &scriptDNSError{"INVALID_SERVER", err.Error()}
	}
	if len(servers) != 1 {
		return dns.NameServer{}, protocol, &scriptDNSError{"INVALID_SERVER", fmt.Sprintf("%q is %d name servers, not one", server, len(servers))}
	}
	nameServer := servers[0]
	if want := map[string]string{"udp": "", "doh": "https", "doh3": "https", "quic": "quic"}[protocol]; nameServer.Net != want {
		return dns.NameServer{}, protocol, &scriptDNSError{"INVALID_SERVER", fmt.Sprintf("%q is not a %s server", server, protocol)}
	}
	if protocol == "doh3" {
		nameServer.Params = maps.Clone(nameServer.Params)
		if nameServer.Params == nil {
			nameServer.Params = map[string]string{}
		}
		nameServer.Params["h3"] = "true"
	}
	if nameServer.ProxyName == "" {
		nameServer.ProxyName = dns.RespectRules
	}
	return nameServer, protocol, nil
}

func scriptDNSServerShown(protocol string, server dns.NameServer) string {
	if protocol == "quic" {
		return "quic://" + server.Addr
	}
	return server.Addr
}

func (q *scriptDNSRequest) ask(ctx context.Context) (*scriptDNSAnswer, *scriptDNSError) {
	if q.protocol == "auto" {
		installed := resolver.DefaultResolver
		if installed == nil {
			return nil, &scriptDNSError{"UNAVAILABLE", "DNS section is disabled"}
		}
		cached := func(m *D.Msg) bool {
			return explainableResolver(installed).HoldsAnswer(m.Question[0])
		}
		return q.rounds(ctx, installed.ExchangeContext, cached)
	}
	if status := tunnel.Status(); status != tunnel.Running {
		return nil, &scriptDNSError{"UNAVAILABLE", fmt.Sprintf("the tunnel is %s, and a named server is asked through it", status)}
	}
	client := dns.NewStandaloneClient(q.server, resolver.DefaultResolver)
	defer client.ResetConnection()
	return q.rounds(ctx, client.ExchangeContext, nil)
}

type scriptDNSRound struct {
	reply  *D.Msg
	cached bool
	err    error
}

func (q *scriptDNSRequest) rounds(ctx context.Context, exchange func(context.Context, *D.Msg) (*D.Msg, error), cached func(*D.Msg) bool) (*scriptDNSAnswer, *scriptDNSError) {
	results := make([]scriptDNSRound, len(q.types))
	var wait sync.WaitGroup
	for i, queryType := range q.types {
		wait.Add(1)
		go func() {
			defer wait.Done()
			results[i] = q.round(ctx, queryType, exchange, cached)
		}()
	}
	wait.Wait()

	answer := &scriptDNSAnswer{Domain: q.domain, Protocol: q.protocol, Server: q.shown, FromCache: cached != nil, Answers: []scriptDNSRecord{}}
	var failure error
	var codes []string
	for _, result := range results {
		if result.err != nil {
			if failure == nil {
				failure = result.err
			}
			continue
		}
		answer.FromCache = answer.FromCache && result.cached
		if result.reply.Rcode != D.RcodeSuccess {
			codes = lo.Uniq(append(codes, D.RcodeToString[result.reply.Rcode]))
		}
		for _, record := range result.reply.Answer {
			header := record.Header()
			answer.Answers = append(answer.Answers, scriptDNSRecord{
				Name:  header.Name,
				Type:  D.TypeToString[header.Rrtype],
				Value: lo.Substring(record.String(), len(header.String()), math.MaxUint),
				TTL:   header.Ttl,
			})
		}
	}
	if len(answer.Answers) > 0 {
		return answer, nil
	}
	answer.FromCache = false
	if failure != nil {
		return nil, scriptDNSFailure(failure)
	}
	if len(codes) > 0 {
		return nil, &scriptDNSError{"NO_ANSWER", q.domain + ": " + strings.Join(codes, ", ")}
	}
	return nil, &scriptDNSError{"NO_ANSWER", fmt.Sprintf("%s has no %s record", q.domain, strings.Join(q.typeNames(), " or "))}
}

func (q *scriptDNSRequest) round(ctx context.Context, queryType uint16, exchange func(context.Context, *D.Msg) (*D.Msg, error), cached func(*D.Msg) bool) scriptDNSRound {
	slots := scriptDNSSlots.get()
	select {
	case slots <- struct{}{}:
	case <-ctx.Done():
		return scriptDNSRound{err: fmt.Errorf("waited for one of %d query slots: %w", scriptDNSRoundsAtOnce, ctx.Err())}
	}
	defer func() { <-slots }()
	roundContext, cancel := context.WithTimeout(ctx, q.timeout)
	defer cancel()
	message := new(D.Msg)
	message.SetQuestion(D.Fqdn(q.domain), queryType)
	fromCache := cached != nil && cached(message)
	reply, err := exchange(roundContext, message)
	if err == nil && reply == nil {
		err = errors.New("the server answered nothing")
	}
	return scriptDNSRound{reply: reply, cached: fromCache, err: err}
}

func scriptDNSFailure(err error) *scriptDNSError {
	var netError net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) || (errors.As(err, &netError) && netError.Timeout()) {
		return &scriptDNSError{"TIMEOUT", err.Error()}
	}
	return &scriptDNSError{"QUERY_FAILED", err.Error()}
}

func (q *scriptDNSRequest) typeNames() []string {
	return lo.Map(q.types, func(queryType uint16, _ int) string { return D.TypeToString[queryType] })
}

func (q *scriptDNSRequest) log(took time.Duration, answer *scriptDNSAnswer, failure *scriptDNSError) {
	asked := lo.Compact([]string{q.protocol, q.shown, q.domain, strings.Join(q.typeNames(), ",")})
	if failure != nil {
		log.Warnln("[script-dns] %s → %s: %s in %d ms", strings.Join(asked, " "), failure.Code, failure.Message, took.Milliseconds())
		return
	}
	log.Infoln("[script-dns] %s → %d answers in %d ms", strings.Join(asked, " "), len(answer.Answers), took.Milliseconds())
}
