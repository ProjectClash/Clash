package clash

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/ProjectClash/Clash/adapter"
	"github.com/ProjectClash/Clash/adapter/outboundgroup"
	adapterprovider "github.com/ProjectClash/Clash/adapter/provider"
	C "github.com/ProjectClash/Clash/constant"
	P "github.com/ProjectClash/Clash/constant/provider"
	"github.com/ProjectClash/Clash/hub/route"
	"github.com/ProjectClash/Clash/tunnel"
	"github.com/metacubex/chi"
	mhttp "github.com/metacubex/http"
)

func init() {
	route.Register(func(router chi.Router) {
		for _, prefix := range privateRoutePrefixes {
			router.Get(prefix+"/proxies-summary", serveNodeView(func(v nodeView, q url.Values) (string, int) {
				return v.summaryJSON(), mhttp.StatusOK
			}))
			router.Get(prefix+"/proxies-page", serveProxiesPage)
			router.Get(prefix+"/group-members", serveNodeView(func(v nodeView, q url.Values) (string, int) {
				offset, _ := strconv.Atoi(q.Get("offset"))
				limit, _ := strconv.Atoi(q.Get("limit"))
				return v.membersAnswer(q.Get("group"), offset, limit)
			}))
			router.Get(prefix+"/group-members-search", serveNodeView(func(v nodeView, q url.Values) (string, int) {
				offset, _ := strconv.Atoi(q.Get("offset"))
				limit, _ := strconv.Atoi(q.Get("limit"))
				return v.memberSearchAnswer(q.Get("group"), q.Get("query"), offset, limit)
			}))
			router.Get(prefix+"/proxy-lookup", serveNodeView(func(v nodeView, q url.Values) (string, int) {
				return v.lookupAnswer(q.Get("name"))
			}))
			router.Get(prefix+"/proxies-search", serveNodeView(func(v nodeView, q url.Values) (string, int) {
				offset, _ := strconv.Atoi(q.Get("offset"))
				limit, _ := strconv.Atoi(q.Get("limit"))
				return v.searchAnswer(q.Get("query"), offset, limit)
			}))
			router.Get(prefix+"/provider-nodes", serveNodeView(func(v nodeView, q url.Values) (string, int) {
				offset, _ := strconv.Atoi(q.Get("offset"))
				limit, _ := strconv.Atoi(q.Get("limit"))
				return v.providerNodesAnswer(q.Get("provider"), offset, limit)
			}))
		}
	})
}

type nodeView struct {
	proxies   map[string]C.Proxy
	library   C.ProxyLibrary
	providers map[string]P.ProxyProvider
	table     *uint64
}

func runningNodeView() nodeView {
	proxies, providers, table := tunnel.ProxyTable()
	return nodeView{proxies: proxies, library: tunnel.ProxyLibrary(), providers: providers, table: &table}
}

func serveNodeView(answer func(v nodeView, q url.Values) (string, int)) mhttp.HandlerFunc {
	return func(writer mhttp.ResponseWriter, request *mhttp.Request) {
		body, status := answer(runningNodeView(), request.URL.Query())
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("Cache-Control", "no-store")
		writer.WriteHeader(status)
		_, _ = io.WriteString(writer, body)
	}
}

func serveProxiesPage(writer mhttp.ResponseWriter, request *mhttp.Request) {
	query := request.URL.Query()
	limit, _ := strconv.Atoi(query.Get("limit"))
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(mhttp.StatusOK)
	_ = runningNodeView().writeProxiesPage(writer, query.Get("after"), limit)
}

func (v nodeView) groupMembers(group string) (C.ProxyList, bool) {
	proxy, found := v.proxies[group]
	if !found {
		return nil, false
	}
	holder, isGroup := proxy.Adapter().(interface{ Members(bool) C.ProxyList })
	if _, ok := proxy.Adapter().(outboundgroup.ProxyGroup); !ok || !isGroup {
		return nil, false
	}
	return holder.Members(false), true
}

func appendGroupSummary(b []byte, group C.Proxy, _ C.ProxyList) ([]byte, error) {
	return adapter.AppendProxySummaryJSON(b, group)
}

func (v nodeView) appendPageEntry(b []byte, proxy C.Proxy) ([]byte, error) {
	if members, ok := v.groupMembers(proxy.Name()); ok && v.proxies[proxy.Name()] == proxy {
		return appendGroupSummary(b, proxy, members)
	}
	return adapter.AppendProxyJSON(b, proxy)
}

func (v nodeView) writeProxiesPage(w io.Writer, after string, limit int) error {
	if _, err := io.WriteString(w, `{"proxies":`); err != nil {
		return err
	}
	next, err := adapter.WriteProxiesJSONPageFunc(w, v.proxies, v.library, after, max(limit, 0), v.appendPageEntry)
	if err != nil {
		return err
	}
	tail := []byte{}
	if next != "" {
		tail = append(tail, `,"next":`...)
		tail = appendJSONString(tail, next)
	}
	tail = append(tail, '}')
	_, err = w.Write(tail)
	return err
}

func (v nodeView) proxiesPageJSON(after string, limit int) string {
	var b bytes.Buffer
	if err := v.writeProxiesPage(&b, after, limit); err != nil {
		return mustJSON(map[string]any{"error": err.Error()})
	}
	return b.String()
}

func (v nodeView) ownNode(member C.Proxy) bool {
	name := member.Name()
	if p, ok := v.proxies[name]; ok {
		return p == member
	}
	if v.library != nil {
		if p, ok := v.library.Lookup(name); ok {
			return p == member
		}
	}
	return false
}

func placeholderType(member C.Proxy) string {
	if adapter.IsLibraryNode(member) {
		return ""
	}
	if declared, ok := member.Adapter().(interface{ ClashDeclaredType() C.AdapterType }); ok {
		return strings.ToLower(declared.ClashDeclaredType().String())
	}
	return ""
}

func (v nodeView) ownNodeCount() int {
	count := 0
	for name := range v.proxies {
		if _, isGroup := v.groupMembers(name); !isGroup && !slices.Contains(builtinProxyNames[:], name) {
			count++
		}
	}
	if v.library != nil {
		count += v.library.Len()
	}
	return count
}

func pageBounds(total, offset, limit int) (int, int) {
	offset = min(max(offset, 0), total)
	end := total
	if limit > 0 && offset+limit < total {
		end = offset + limit
	}
	return offset, end
}

func (v nodeView) consistentPage(page func() (string, int)) (string, int) {
	for attempt := 0; attempt < 3; attempt++ {
		before := string(v.appendRevision(nil))
		answer, status := page()
		if before == string(v.appendRevision(nil)) {
			return answer, status
		}
	}
	return `{"error":"the node list is changing; read it again"}`, mhttp.StatusServiceUnavailable
}

func (v nodeView) membersAnswer(group string, offset, limit int) (string, int) {
	return v.consistentPage(func() (string, int) { return v.membersPage(group, offset, limit) })
}

func (v nodeView) membersPage(group string, offset, limit int) (string, int) {
	if group == "" {
		return `{"error":"no group named"}`, mhttp.StatusBadRequest
	}
	members, ok := v.groupMembers(group)
	if !ok {
		return `{"error":"no such group"}`, mhttp.StatusNotFound
	}
	total := members.Len()
	offset, end := pageBounds(total, offset, limit)
	b := make([]byte, 0, 96+(end-offset)*48)
	b = append(b, '{')
	b = v.appendRevision(b)
	b = append(b, `"group":`...)
	b = appendJSONString(b, group)
	b = append(b, `,"total":`...)
	b = strconv.AppendInt(b, int64(total), 10)
	b = append(b, `,"members":[`...)
	for i := offset; i < end; i++ {
		if i > offset {
			b = append(b, ',')
		}
		b = v.appendMember(b, members.At(i))
	}
	b = append(b, "]}"...)
	return string(b), mhttp.StatusOK
}

func (v nodeView) memberSearchAnswer(group, query string, offset, limit int) (string, int) {
	return v.consistentPage(func() (string, int) { return v.memberSearchPage(group, query, offset, limit) })
}

func (v nodeView) memberSearchPage(group, query string, offset, limit int) (string, int) {
	if group == "" {
		return `{"error":"no group named"}`, mhttp.StatusBadRequest
	}
	if strings.TrimSpace(query) == "" {
		return `{"error":"no query"}`, mhttp.StatusBadRequest
	}
	members, ok := v.groupMembers(group)
	if !ok {
		return `{"error":"no such group"}`, mhttp.StatusNotFound
	}
	if offset < 0 {
		offset = 0
	}
	b := make([]byte, 0, 256)
	b = append(b, '{')
	b = v.appendRevision(b)
	b = append(b, `"group":`...)
	b = appendJSONString(b, group)
	b = append(b, `,"members":[`...)
	total, written := 0, 0
	for i := 0; i < members.Len(); i++ {
		member := members.At(i)
		if !containsFold(member.Name(), query) {
			continue
		}
		if total >= offset && (limit <= 0 || written < limit) {
			if written > 0 {
				b = append(b, ',')
			}
			b = v.appendMember(b, member)
			written++
		}
		total++
	}
	b = append(b, `],"total":`...)
	b = strconv.AppendInt(b, int64(total), 10)
	b = append(b, '}')
	return string(b), mhttp.StatusOK
}

func (v nodeView) providerNodesAnswer(name string, offset, limit int) (string, int) {
	return v.consistentPage(func() (string, int) { return v.providerNodesPage(name, offset, limit) })
}

func (v nodeView) providerNodesPage(name string, offset, limit int) (string, int) {
	if name == "" {
		return `{"error":"no provider named"}`, mhttp.StatusBadRequest
	}
	provider, ok := v.providers[name]
	if !ok {
		return `{"error":"no such provider"}`, mhttp.StatusNotFound
	}
	nodes := provider.ProxyList()
	total := 0
	if nodes != nil {
		total = nodes.Len()
	}
	offset, end := pageBounds(total, offset, limit)
	b := make([]byte, 0, 96+(end-offset)*256)
	b = append(b, '{')
	b = v.appendRevision(b)
	b = append(b, `"provider":`...)
	b = appendJSONString(b, name)
	b = append(b, `,"total":`...)
	b = strconv.AppendInt(b, int64(total), 10)
	b = append(b, `,"proxies":[`...)
	for i := offset; i < end; i++ {
		if i > offset {
			b = append(b, ',')
		}
		var err error
		if b, err = adapter.AppendProxyJSON(b, nodes.At(i)); err != nil {
			return mustJSON(map[string]any{"error": err.Error()}), mhttp.StatusInternalServerError
		}
	}
	b = append(b, "]}"...)
	return string(b), mhttp.StatusOK
}

const searchLimit = 200

func containsFold(s, sub string) bool {
	if sub == "" {
		return true
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if strings.EqualFold(s[i:i+len(sub)], sub) {
			return true
		}
	}
	return false
}

func (v nodeView) searchAnswer(query string, offset, limit int) (string, int) {
	if strings.TrimSpace(query) == "" {
		return `{"error":"no query"}`, mhttp.StatusBadRequest
	}
	if limit <= 0 || limit > searchLimit {
		limit = searchLimit
	}
	offset = max(offset, 0)
	b := make([]byte, 0, 1024)
	total := 0
	match := func(proxy C.Proxy, source string) {
		name := proxy.Name()
		if !containsFold(name, query) {
			return
		}
		if total >= offset && total < offset+limit {
			if total > offset {
				b = append(b, ',')
			}
			b = append(b, `{"name":`...)
			b = appendJSONString(b, name)
			b = append(b, `,"type":`...)
			b = appendJSONString(b, proxy.Type().String())
			b = append(b, `,"source":`...)
			b = appendJSONString(b, source)
			b = append(b, '}')
		}
		total++
	}
	names := make([]string, 0, len(v.proxies))
	for name := range v.proxies {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if _, isGroup := v.groupMembers(name); isGroup {
			match(v.proxies[name], "group")
		}
	}
	var sorted C.ProxyList = C.ProxySlice(nil)
	if nodes, ok := v.library.(*adapter.LibraryNodes); ok && nodes != nil {
		sorted = nodes.Sorted()
	}
	j := 0
	for _, name := range names {
		if _, isGroup := v.groupMembers(name); isGroup {
			continue
		}
		for ; j < sorted.Len() && sorted.At(j).Name() < name; j++ {
			match(sorted.At(j), "inline")
		}
		match(v.proxies[name], "inline")
	}
	for ; j < sorted.Len(); j++ {
		match(sorted.At(j), "inline")
	}
	providerNames := make([]string, 0, len(v.providers))
	for name, provider := range v.providers {
		if provider.VehicleType() != P.Compatible {
			providerNames = append(providerNames, name)
		}
	}
	sort.Strings(providerNames)
	for _, name := range providerNames {
		nodes := v.providers[name].ProxyList()
		for i := 0; nodes != nil && i < nodes.Len(); i++ {
			match(nodes.At(i), name)
		}
	}
	head := make([]byte, 0, len(b)+64+len(query))
	head = append(head, `{"query":`...)
	head = appendJSONString(head, query)
	head = append(head, `,"total":`...)
	head = strconv.AppendInt(head, int64(total), 10)
	head = append(head, `,"items":[`...)
	head = append(head, b...)
	head = append(head, "]}"...)
	return string(head), mhttp.StatusOK
}

func (v nodeView) appendRevision(b []byte) []byte {
	if v.table == nil {
		return b
	}
	var versions uint64
	for _, provider := range v.providers {
		if provider.VehicleType() != P.Compatible {
			versions += uint64(provider.Version())
		}
	}
	b = append(b, `"revision":"`...)
	b = append(b, proxyDelaysProcess...)
	b = append(b, '.')
	b = strconv.AppendUint(b, *v.table, 10)
	b = append(b, '.')
	b = strconv.AppendUint(b, versions, 10)
	return append(b, `",`...)
}

func (v nodeView) appendNowMember(b []byte, start int, group C.Proxy) []byte {
	selectable, ok := group.Adapter().(outboundgroup.ProxyGroup)
	if !ok || len(b) == 0 || b[len(b)-1] != '}' {
		return b
	}
	member, found := outboundgroup.ClashNowMember(selectable)
	if !found {
		return b
	}
	var written struct {
		Now *string `json:"now"`
	}
	if json.Unmarshal(b[start:], &written) != nil || written.Now == nil || *written.Now != member.Name() {
		return b
	}
	b = b[:len(b)-1]
	b = append(b, `,"nowMember":`...)
	b = v.appendMember(b, member)
	return append(b, '}')
}

func (v nodeView) appendMember(b []byte, member C.Proxy) []byte {
	b = append(b, `{"name":`...)
	b = appendJSONString(b, member.Name())
	b = append(b, `,"type":`...)
	b = appendJSONString(b, member.Type().String())
	if placeholder := placeholderType(member); placeholder != "" {
		b = append(b, `,"placeholderType":`...)
		b = appendJSONString(b, placeholder)
	}
	b = append(b, `,"inline":`...)
	b = strconv.AppendBool(b, v.ownNode(member))
	return append(b, '}')
}

func (v nodeView) groupOrder() []string {
	var order []string
	if all, ok := v.providers[adapterprovider.ReservedName]; ok {
		if list := all.ProxyList(); list != nil {
			start := list.Len()
			for start > 0 {
				if _, isGroup := v.groupMembers(list.At(start - 1).Name()); !isGroup {
					break
				}
				start--
			}
			for i := start; i < list.Len(); i++ {
				order = append(order, list.At(i).Name())
			}
		}
	}
	if _, global := v.groupMembers("GLOBAL"); global && !slices.Contains(order, "GLOBAL") {
		order = append(order, "GLOBAL")
	}
	return order
}

func (v nodeView) lookupAnswer(name string) (string, int) {
	if name == "" {
		return `{"error":"no name"}`, mhttp.StatusBadRequest
	}
	b := []byte(`{"name":`)
	b = appendJSONString(b, name)
	proxy, found := v.proxies[name]
	if !found && v.library != nil {
		proxy, found = v.library.Lookup(name)
	}
	if !found {
		return string(append(b, `,"found":false}`...)), mhttp.StatusOK
	}
	source := "inline"
	if _, isGroup := v.groupMembers(name); isGroup {
		source = "group"
	}
	b = append(b, `,"found":true,"type":`...)
	b = appendJSONString(b, proxy.Type().String())
	b = append(b, `,"source":`...)
	b = appendJSONString(b, source)
	return string(append(b, '}')), mhttp.StatusOK
}

func (v nodeView) summaryJSON() string {
	names := make([]string, 0, len(v.proxies))
	for name := range v.proxies {
		names = append(names, name)
	}
	sort.Strings(names)
	total := len(v.proxies)
	if v.library != nil {
		total += v.library.Len()
	}
	b := make([]byte, 0, 4096)
	b = append(b, '{')
	b = v.appendRevision(b)
	b = append(b, `"total":`...)
	b = strconv.AppendInt(b, int64(total), 10)
	b = append(b, `,"nodes":`...)
	b = strconv.AppendInt(b, int64(v.ownNodeCount()), 10)
	b = append(b, `,"groups":{`...)
	first := true
	for _, name := range names {
		members, ok := v.groupMembers(name)
		if !ok {
			continue
		}
		if !first {
			b = append(b, ',')
		}
		first = false
		b = appendJSONString(b, name)
		b = append(b, ':')
		start := len(b)
		var err error
		if b, err = appendGroupSummary(b, v.proxies[name], members); err != nil {
			return mustJSON(map[string]any{"error": err.Error()})
		}
		b = v.appendNowMember(b, start, v.proxies[name])
	}
	b = append(b, `},"groupOrder":[`...)
	for i, name := range v.groupOrder() {
		if i > 0 {
			b = append(b, ',')
		}
		b = appendJSONString(b, name)
	}
	b = append(b, `],"providers":{`...)
	providerNames := make([]string, 0, len(v.providers))
	for name := range v.providers {
		providerNames = append(providerNames, name)
	}
	sort.Strings(providerNames)
	first = true
	for _, name := range providerNames {
		summary := adapterprovider.ClashProviderSummary(v.providers[name])
		if summary == nil {
			continue
		}
		encoded, err := json.Marshal(summary)
		if err != nil {
			continue
		}
		if !first {
			b = append(b, ',')
		}
		first = false
		b = appendJSONString(b, name)
		b = append(b, ':')
		b = append(b, encoded...)
	}
	b = append(b, "}}"...)
	return string(b)
}

func ProxiesSummaryJSON() string { return bridgeSafeString(runningNodeView().summaryJSON()) }

func ProxiesPageJSON(after string, limit int32) string {
	return bridgeSafeString(runningNodeView().proxiesPageJSON(after, int(limit)))
}

func GroupMembersJSON(group string, offset, limit int32) string {
	answer, _ := runningNodeView().membersAnswer(group, int(offset), int(limit))
	return bridgeSafeString(answer)
}

func SearchGroupMembersJSON(group, query string, offset, limit int32) string {
	answer, _ := runningNodeView().memberSearchAnswer(group, query, int(offset), int(limit))
	return bridgeSafeString(answer)
}

func LookupProxyJSON(name string) string {
	answer, _ := runningNodeView().lookupAnswer(name)
	return bridgeSafeString(answer)
}

func SearchProxiesJSON(query string, offset, limit int32) string {
	answer, _ := runningNodeView().searchAnswer(query, int(offset), int(limit))
	return bridgeSafeString(answer)
}

func ProviderNodesJSON(provider string, offset, limit int32) string {
	answer, _ := runningNodeView().providerNodesAnswer(provider, int(offset), int(limit))
	return bridgeSafeString(answer)
}

func pageQuery(values url.Values, offset, limit int32) string {
	if offset > 0 {
		values.Set("offset", strconv.Itoa(int(offset)))
	}
	if limit > 0 {
		values.Set("limit", strconv.Itoa(int(limit)))
	}
	if encoded := values.Encode(); encoded != "" {
		return "?" + encoded
	}
	return ""
}

func (c *APIClient) GetProxiesSummary() (string, error) {
	answer, err := c.privateRequest(http.MethodGet, "/proxies-summary", nil)
	return bridgeSafeString(answer), bridgeSafeError(err)
}

func (c *APIClient) GetProxiesPage(after string, limit int32) (string, error) {
	values := url.Values{}
	if after != "" {
		values.Set("after", after)
	}
	answer, err := c.privateRequest(http.MethodGet, "/proxies-page"+pageQuery(values, 0, limit), nil)
	return bridgeSafeString(answer), bridgeSafeError(err)
}

func (c *APIClient) GetGroupMembers(group string, offset, limit int32) (string, error) {
	answer, err := c.privateRequest(http.MethodGet, "/group-members"+pageQuery(url.Values{"group": []string{group}}, offset, limit), nil)
	return bridgeSafeString(answer), bridgeSafeError(err)
}

func (c *APIClient) SearchGroupMembers(group, query string, offset, limit int32) (string, error) {
	answer, err := c.privateRequest(http.MethodGet, "/group-members-search"+pageQuery(url.Values{"group": []string{group}, "query": []string{query}}, offset, limit), nil)
	return bridgeSafeString(answer), bridgeSafeError(err)
}

func (c *APIClient) LookupProxy(name string) (string, error) {
	answer, err := c.privateRequest(http.MethodGet, "/proxy-lookup"+pageQuery(url.Values{"name": []string{name}}, 0, 0), nil)
	return bridgeSafeString(answer), bridgeSafeError(err)
}

func (c *APIClient) SearchProxies(query string, offset, limit int32) (string, error) {
	answer, err := c.privateRequest(http.MethodGet, "/proxies-search"+pageQuery(url.Values{"query": []string{query}}, offset, limit), nil)
	return bridgeSafeString(answer), bridgeSafeError(err)
}

func (c *APIClient) GetProviderNodes(provider string, offset, limit int32) (string, error) {
	answer, err := c.privateRequest(http.MethodGet, "/provider-nodes"+pageQuery(url.Values{"provider": []string{provider}}, offset, limit), nil)
	return bridgeSafeString(answer), bridgeSafeError(err)
}
