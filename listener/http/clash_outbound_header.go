package http

import (
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/ProjectClash/Clash/adapter/inbound"
	"github.com/ProjectClash/Clash/component/auth"
	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/log"

	"github.com/metacubex/http"
)


const OutboundHeader = "Clash-Outbound"

type outboundLookup interface {
	LookupProxy(name string) (C.Proxy, bool)
}

func HandleConnNamingOutbound(c net.Conn, tunnel C.Tunnel, store auth.AuthStore, additions ...inbound.Addition) {
	handleConn(c, tunnel, store, true, additions...)
}

func namedOutbound(request *http.Request, tunnel C.Tunnel, additions []inbound.Addition) ([]inbound.Addition, *http.Response) {
	values, present := request.Header[OutboundHeader]
	if !present {
		return additions, nil
	}
	refuse := func(status int, reason string) ([]inbound.Addition, *http.Response) {
		log.Warnln("[HTTP] %s CONNECT %s: %s", request.RemoteAddr, request.Host, reason)
		response := responseWith(request, status)
		response.Header.Set("Content-Type", "text/plain; charset=utf-8")
		response.Body = io.NopCloser(strings.NewReader(reason + "\n"))
		response.ContentLength = int64(len(reason) + 1)
		response.Close = true
		return nil, response
	}
	if len(values) != 1 {
		return refuse(http.StatusBadRequest, fmt.Sprintf("%d %s headers, one is read", len(values), OutboundHeader))
	}
	name, err := url.PathUnescape(values[0])
	if err != nil {
		return refuse(http.StatusBadRequest, fmt.Sprintf("%s %q is not percent-encoding: %v", OutboundHeader, values[0], err))
	}
	if !utf8.ValidString(name) {
		return refuse(http.StatusBadRequest, fmt.Sprintf("%s %q is not UTF-8 once decoded", OutboundHeader, values[0]))
	}
	if name == "" {
		return refuse(http.StatusBadRequest, OutboundHeader+" names no outbound")
	}
	lookup, ok := tunnel.(outboundLookup)
	if !ok {
		return refuse(http.StatusBadGateway, fmt.Sprintf("this core cannot look outbound %q up", name))
	}
	if proxy, found := lookup.LookupProxy(name); !found || proxy == nil {
		return refuse(http.StatusBadGateway, fmt.Sprintf("no outbound named %q", name))
	}
	named := make([]inbound.Addition, len(additions), len(additions)+1)
	copy(named, additions)
	return append(named, inbound.WithSpecialProxy(name)), nil
}
