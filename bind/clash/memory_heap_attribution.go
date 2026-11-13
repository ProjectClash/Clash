package clash

import (
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	C "github.com/ProjectClash/Clash/constant"
	P "github.com/ProjectClash/Clash/constant/provider"
	"github.com/ProjectClash/Clash/log"
	"github.com/ProjectClash/Clash/transport/gun"
	"github.com/ProjectClash/Clash/tunnel"
	mieru "github.com/enfein/mieru/v3/pkg/protocol"
	"github.com/metacubex/smux"
)

type heapAttribution struct {
	Incomplete bool `json:"incomplete,omitempty"`

	UDPSessions    int   `json:"udpSessions"`
	AppQueuedBytes int64 `json:"appQueuedBytes"`
	StalledFlows   int   `json:"stalledFlows"`

	SmuxUnreadBytes  int64 `json:"smuxUnreadBytes"`
	GRPCFlows        int64 `json:"grpcFlows"`
	MieruQueuedBytes int64 `json:"mieruQueuedBytes"`
	MieruSessions    int   `json:"mieruSessions"`

	Hysteria2  quicAttribution `json:"hysteria2"`
	Tuic       quicAttribution `json:"tuic"`
	Hysteria   quicAttribution `json:"hysteria"`
	ShadowQuic quicAttribution `json:"shadowquic"`
	Masque     quicAttribution `json:"masque"`
}

type quicAttribution struct {
	Connections      int   `json:"connections"`
	TCPFlows         int   `json:"tcpFlows"`
	UnreadBoundBytes int64 `json:"unreadBoundBytes"`
}

func quicDefaultMaxWindows(adapterType C.AdapterType) (stream, connection int64, ok bool) {
	windows, ok := quicWindowDefaults(adapterType)
	return windows.maxStream, windows.maxConnection, ok
}

type heapSources struct {
	views       func() []shedView
	nodeType    func() func(name string) (C.AdapterType, bool)
	smuxUnread  func() int64
	grpcFlows   func() int64
	mieruQueued func() (bytes int64, sessions int)
}

func liveHeapSources() heapSources {
	return heapSources{
		views:       liveShedViews,
		nodeType:    liveNodeTypeLookup,
		smuxUnread:  func() int64 { bytes, _ := smux.UnreadBytes(); return bytes },
		grpcFlows:   gun.StreamsOpen,
		mieruQueued: mieru.StreamReceiveQueued,
	}
}

func attributeHeap(sources heapSources) (report heapAttribution) {
	defer func() {
		if recovered := recover(); recovered != nil {
			report = heapAttribution{Incomplete: true}
		}
	}()
	quicOf := map[C.AdapterType]*quicAttribution{
		C.Hysteria2: &report.Hysteria2, C.Tuic: &report.Tuic, C.Hysteria: &report.Hysteria,
		C.ShadowQuic: &report.ShadowQuic, C.Masque: &report.Masque,
	}
	nodeType := sources.nodeType()
	quicNodes := map[C.AdapterType]map[string]int64{}
	for _, view := range sources.views() {
		if view.network == C.UDP {
			report.UDPSessions++
		}
		if view.queuedKnown {
			report.AppQueuedBytes += int64(view.queued)
		}
		if view.stalled() {
			report.StalledFlows++
		}
		adapterType, ok := nodeType(view.node)
		quic := quicOf[adapterType]
		if !ok || quic == nil {
			continue
		}
		if quicNodes[adapterType] == nil {
			quicNodes[adapterType] = map[string]int64{}
		}
		if view.network == C.TCP {
			quicNodes[adapterType][view.node]++
			quic.TCPFlows++
		} else if _, seen := quicNodes[adapterType][view.node]; !seen {
			quicNodes[adapterType][view.node] = 0
		}
	}
	for adapterType, nodes := range quicNodes {
		stream, connection, _ := quicDefaultMaxWindows(adapterType)
		quic := quicOf[adapterType]
		quic.Connections = len(nodes)
		for _, flows := range nodes {
			quic.UnreadBoundBytes += min(flows*stream, connection)
		}
	}
	report.SmuxUnreadBytes = sources.smuxUnread()
	report.GRPCFlows = sources.grpcFlows()
	if sources.mieruQueued != nil {
		report.MieruQueuedBytes, report.MieruSessions = sources.mieruQueued()
	}
	return report
}

func liveNodeTypeLookup() func(name string) (C.AdapterType, bool) {
	var lists []C.ProxyList
	var libraries []C.ProxyLibrary
	for _, provider := range tunnel.Providers() {
		if provider.VehicleType() == P.Compatible {
			continue
		}
		list := provider.ProxyList()
		if library, ok := list.(C.ProxyLibrary); ok {
			libraries = append(libraries, library)
			continue
		}
		lists = append(lists, list)
	}
	type answer struct {
		adapterType C.AdapterType
		ok          bool
	}
	answered := map[string]answer{}
	return func(name string) (C.AdapterType, bool) {
		if known, seen := answered[name]; seen {
			return known.adapterType, known.ok
		}
		known := func() answer {
			for i := len(lists) - 1; i >= 0; i-- {
				for j := lists[i].Len() - 1; j >= 0; j-- {
					if proxy := lists[i].At(j); proxy.Name() == name {
						return answer{proxy.Type(), true}
					}
				}
			}
			for _, library := range libraries {
				if proxy, ok := library.Lookup(name); ok {
					return answer{proxy.Type(), true}
				}
			}
			if proxy, ok := lookupRunningProxy(name); ok {
				return answer{proxy.Type(), true}
			}
			return answer{}
		}()
		answered[name] = known
		return known.adapterType, known.ok
	}
}

func currentHeapAttribution() heapAttribution {
	return attributeHeap(liveHeapSources())
}

func (a heapAttribution) logLine() string {
	if a.Incomplete {
		return "[Memory] heap attribution: not counted (counting failed)"
	}
	parts := []string{fmt.Sprintf("%d UDP sessions", a.UDPSessions),
		fmt.Sprintf("%s held for apps, %d flows stalled on it", byteSize(a.AppQueuedBytes), a.StalledFlows)}
	if a.SmuxUnreadBytes != 0 {
		parts = append(parts, "smux sessions of every kind "+byteSize(a.SmuxUnreadBytes)+" unread")
	}
	if a.GRPCFlows != 0 {
		parts = append(parts, fmt.Sprintf("gRPC %d flows open", a.GRPCFlows))
	}
	if a.MieruSessions != 0 {
		parts = append(parts, fmt.Sprintf("mieru %d sessions %s unread", a.MieruSessions, byteSize(a.MieruQueuedBytes)))
	}
	for _, quic := range []struct {
		name string
		quic quicAttribution
	}{{"Hysteria2", a.Hysteria2}, {"TUIC", a.Tuic}, {"Hysteria", a.Hysteria}, {"ShadowQUIC", a.ShadowQuic}, {"MASQUE", a.Masque}} {
		switch {
		case quic.quic.Connections != 0 && quic.quic.TCPFlows == 0:
			parts = append(parts, fmt.Sprintf("%s %d connections, datagrams only", quic.name, quic.quic.Connections))
		case quic.quic.Connections != 0:
			parts = append(parts, fmt.Sprintf("%s %d connections %d TCP flows, at most %s unread "+
				"(bound from the default windows, one connection a node; not measured)",
				quic.name, quic.quic.Connections, quic.quic.TCPFlows, byteSize(quic.quic.UnreadBoundBytes)))
		}
	}
	return "[Memory] heap attribution: " + strings.Join(parts, "; ")
}

func byteSize(bytes int64) string {
	if bytes < 1<<10 {
		return fmt.Sprintf("%d B", bytes)
	}
	if bytes < 1<<20 {
		return fmt.Sprintf("%d KiB", bytes>>10)
	}
	return fmt.Sprintf("%.1f MiB", float64(bytes)/(1<<20))
}

const (
	heapAttributionCriticalEvery = 5 * time.Second
	heapAttributionShedEvery     = 30 * time.Second
)

var (
	heapAttributionClock          = time.Now()
	heapAttributionCriticalLogged atomic.Int64
	heapAttributionShedLogged     atomic.Int64
)

func heapAttributionDue(last *atomic.Int64, every time.Duration) bool {
	now := int64(time.Since(heapAttributionClock)) + 1
	previous := last.Load()
	if previous != 0 && time.Duration(now-previous) < every {
		return false
	}
	return last.CompareAndSwap(previous, now)
}

func criticalHeapAttributionLineDue() bool {
	return heapAttributionDue(&heapAttributionCriticalLogged, heapAttributionCriticalEvery)
}

func logShedHeapAttribution() {
	if log.Level() > log.WARNING {
		return
	}
	if heapAttributionDue(&heapAttributionShedLogged, heapAttributionShedEvery) {
		log.Warnln("[Memory] layer 3: %s", strings.TrimPrefix(currentHeapAttribution().logLine(), "[Memory] "))
	}
}
