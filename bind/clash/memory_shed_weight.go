package clash

import (
	"sort"
	"time"

	C "github.com/ProjectClash/Clash/constant"
	P "github.com/ProjectClash/Clash/constant/provider"
	"github.com/ProjectClash/Clash/tunnel"
	"github.com/ProjectClash/Clash/tunnel/statistic"
)

const (
	shedTCPBaseBytes      int64 = 57 << 10
	shedUDPBaseBytes      int64 = 56 << 10
	shedStallAfter              = 2 * time.Second
	shedMinAge                  = 2 * time.Second
	shedWedgedIdle              = 10 * time.Second
	shedUnknownQUICWindow int64 = 1 << 20
)

func quicWindow(adapterType C.AdapterType) (stream, connection int64, ok bool) {
	switch adapterType {
	case C.Hysteria2:
		return 8 << 20, 20 << 20, true
	case C.Tuic:
		return 15728640 / 10, 67108864 / 10, true
	case C.Hysteria:
		return 15728640, 67108864, true
	case C.ShadowQuic, C.Masque:
		return shedUnknownQUICWindow, shedUnknownQUICWindow, true
	}
	return 0, 0, false
}

type shedView struct {
	id            string
	network       C.NetWork
	node          string
	age           time.Duration
	sinceDownload time.Duration
	sinceUpload   time.Duration
	queued        int
	queuedKnown   bool
	tracker       statistic.Tracker
}

func (v shedView) idle() time.Duration {
	if v.sinceUpload < v.sinceDownload {
		return v.sinceUpload
	}
	return v.sinceDownload
}

func (v shedView) stalled() bool {
	return v.network == C.TCP && v.queuedKnown && v.queued > 0 && v.sinceDownload >= shedStallAfter
}

type shedCandidate struct {
	shedView
	weight int64
	group  string
}

func rankShedCandidates(views []shedView, nodeType func(name string) (C.AdapterType, bool)) []shedCandidate {
	isQUIC := func(node string) bool {
		adapterType, ok := nodeType(node)
		if !ok {
			return false
		}
		_, _, quic := quicWindow(adapterType)
		return quic
	}
	stalledOnNode := map[string]int64{}
	notStuck := map[string]bool{}
	for _, view := range views {
		stalled := view.stalled()
		if stalled {
			stalledOnNode[view.node]++
		}
		if view.sinceUpload < shedWedgedIdle || (!stalled && view.idle() < shedWedgedIdle) {
			notStuck[view.node] = true
		}
	}
	candidates := make([]shedCandidate, 0, len(views))
	for _, view := range views {
		group := ""
		if stalledOnNode[view.node] > 0 && isQUIC(view.node) {
			if notStuck[view.node] {
				continue
			}
			group = view.node
		} else if view.age < shedMinAge {
			continue
		}
		weight := shedTCPBaseBytes
		if view.network == C.UDP {
			weight = shedUDPBaseBytes
		}
		if view.queuedKnown {
			weight += int64(view.queued)
		}
		if group != "" && view.stalled() {
			if adapterType, ok := nodeType(view.node); ok {
				stream, connection, _ := quicWindow(adapterType)
				weight += min(stream, connection/stalledOnNode[view.node])
			}
		}
		candidates = append(candidates, shedCandidate{shedView: view, weight: weight, group: group})
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].weight != candidates[j].weight {
			return candidates[i].weight > candidates[j].weight
		}
		if candidates[i].idle() != candidates[j].idle() {
			return candidates[i].idle() > candidates[j].idle()
		}
		return candidates[i].id < candidates[j].id
	})
	return candidates
}

func liveShedViews() []shedView {
	now := time.Now()
	var views []shedView
	statistic.DefaultManager.Range(func(tracker statistic.Tracker) bool {
		info := tracker.Info()
		activity, ok := tracker.(statistic.Activity)
		if info == nil || info.Metadata == nil || !ok {
			return true
		}
		view := shedView{
			id:            tracker.ID(),
			network:       info.Metadata.NetWork,
			age:           now.Sub(info.Start),
			sinceDownload: activity.SinceDownload(),
			sinceUpload:   activity.SinceUpload(),
			tracker:       tracker,
		}
		if len(info.Chain) > 0 {
			view.node = info.Chain[0]
		}
		view.queued, view.queuedKnown = activity.InboundQueued()
		views = append(views, view)
		return true
	})
	return views
}

func liveNodeTypes() func(name string) (C.AdapterType, bool) {
	types := map[string]C.AdapterType{}
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
		for i := 0; i < list.Len(); i++ {
			proxy := list.At(i)
			types[proxy.Name()] = proxy.Type()
		}
	}
	return func(name string) (C.AdapterType, bool) {
		if adapterType, ok := types[name]; ok {
			return adapterType, true
		}
		for _, library := range libraries {
			if proxy, ok := library.Lookup(name); ok {
				return proxy.Type(), true
			}
		}
		if proxy, ok := lookupRunningProxy(name); ok {
			return proxy.Type(), true
		}
		return 0, false
	}
}
