package tunnel

import (
	"bytes"
	"io"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	N "github.com/ProjectClash/Clash/common/net"
	C "github.com/ProjectClash/Clash/constant"
	RC "github.com/ProjectClash/Clash/rules/common"
)


type rejectPageCopy struct {
	lang, title, line string
}

var (
	rejectPageEnglish = rejectPageCopy{"en", "Blocked", "This page was blocked on this device."}
	rejectPageHans    = rejectPageCopy{"zh-Hans", "已拦截", "这个网页在这台设备上被拦截了。"}
	rejectPageHant    = rejectPageCopy{"zh-Hant", "已攔截", "這個網頁在這台裝置上被攔截了。"}
)

func (c rejectPageCopy) response() []byte {
	body := "<!doctype html><html lang=\"" + c.lang + "\"><head><meta charset=\"utf-8\">" +
		"<meta name=\"viewport\" content=\"width=device-width\"><title>" + c.title + "</title></head>" +
		"<body style=\"font-family:-apple-system,sans-serif;margin:3em auto;max-width:32em;padding:0 1em\">" +
		"<h1>" + c.title + "</h1><p>" + c.line + "</p></body></html>"
	return []byte("HTTP/1.1 403 Forbidden\r\nContent-Type: text/html; charset=utf-8\r\nContent-Language: " + c.lang +
		"\r\nCache-Control: no-store\r\nConnection: close\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body)
}

var (
	rejectPagesOnce  sync.Once
	rejectPagesBuilt map[string][]byte
)

func rejectPages() map[string][]byte {
	rejectPagesOnce.Do(func() {
		rejectPagesBuilt = map[string][]byte{
			rejectPageEnglish.lang: rejectPageEnglish.response(),
			rejectPageHans.lang:    rejectPageHans.response(),
			rejectPageHant.lang:    rejectPageHant.response(),
		}
	})
	return rejectPagesBuilt
}

func rejectPageLanguage(acceptLanguage string) string {
	type tag struct {
		name string
		q    float64
	}
	var tags []tag
	for _, part := range strings.Split(acceptLanguage, ",") {
		name, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		q := 1.0
		if value, ok := strings.CutPrefix(strings.TrimSpace(params), "q="); ok {
			if parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64); err == nil {
				q = parsed
			}
		}
		if name = strings.ToLower(strings.TrimSpace(name)); name != "" && q > 0 {
			tags = append(tags, tag{name, q})
		}
	}
	sort.SliceStable(tags, func(i, j int) bool { return tags[i].q > tags[j].q })
	for _, t := range tags {
		subtags := strings.Split(t.name, "-")
		switch subtags[0] {
		case "zh":
			for _, subtag := range subtags[1:] {
				switch subtag {
				case "hant", "tw", "hk", "mo":
					return rejectPageHant.lang
				case "hans":
					return rejectPageHans.lang
				}
			}
			return rejectPageHans.lang
		case "en":
			return rejectPageEnglish.lang
		}
	}
	return rejectPageEnglish.lang
}

const rejectPageHeadersWait = 200 * time.Millisecond

func acceptLanguageOf(head []byte) string {
	if end := bytes.Index(head, []byte("\r\n\r\n")); end >= 0 {
		head = head[:end]
	}
	for _, line := range bytes.Split(head, []byte("\r\n"))[1:] {
		name, value, found := bytes.Cut(line, []byte(":"))
		if found && strings.EqualFold(string(bytes.TrimSpace(name)), "accept-language") {
			return string(bytes.TrimSpace(value))
		}
	}
	return ""
}

func answerRejectWithPage(conn *N.BufferedConn, peek *sync.Mutex, metadata *C.Metadata) bool {
	if N.HandshakePending(conn) {
		if metadata.DstPort != 80 {
			return false
		}
		if err := N.ReportDeferredHandshake(conn, nil); err != nil {
			return false
		}
	}
	if tcpProtocolProbe(conn, peek, metadata)() != RC.ProtocolHTTP {
		return false
	}
	peek.Lock()
	defer peek.Unlock()
	_ = conn.SetReadDeadline(time.Now().Add(rejectPageHeadersWait))
	head, _ := conn.Peek(conn.Buffered())
	for !bytes.Contains(head, []byte("\r\n\r\n")) && conn.Buffered() < conn.Reader().Size() {
		if _, err := conn.Peek(conn.Buffered() + 1); err != nil {
			break
		}
		head, _ = conn.Peek(conn.Buffered())
	}
	_ = conn.SetReadDeadline(time.Time{})
	page := rejectPages()[rejectPageLanguage(acceptLanguageOf(head))]
	_, _ = conn.Discard(conn.Buffered())
	_, _ = conn.Write(page)
	_ = conn.SetReadDeadline(time.Now().Add(rejectPageLinger))
	_, _ = io.CopyN(io.Discard, conn, rejectPageLingerBytes)
	_ = conn.SetReadDeadline(time.Time{})
	return true
}

const (
	rejectPageLinger      = 500 * time.Millisecond
	rejectPageLingerBytes = 64 << 10
)
