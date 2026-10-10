package statistic

import (
	"os"
	syncatomic "sync/atomic"
	"time"

	"github.com/ProjectClash/Clash/common/atomic"
	"github.com/ProjectClash/Clash/common/xsync"
	"github.com/ProjectClash/Clash/component/memory"
)

var DefaultManager *Manager

func init() {
	DefaultManager = &Manager{
		uploadTemp:         atomic.NewInt64(0),
		downloadTemp:       atomic.NewInt64(0),
		uploadBlip:         atomic.NewInt64(0),
		downloadBlip:       atomic.NewInt64(0),
		uploadTotal:        atomic.NewInt64(0),
		downloadTotal:      atomic.NewInt64(0),
		proxyUploadTemp:    atomic.NewInt64(0),
		proxyDownloadTemp:  atomic.NewInt64(0),
		proxyUploadBlip:    atomic.NewInt64(0),
		proxyDownloadBlip:  atomic.NewInt64(0),
		proxyUploadTotal:   atomic.NewInt64(0),
		proxyDownloadTotal: atomic.NewInt64(0),
		pid:                int32(os.Getpid()),
		lastReadAt:         atomic.NewInt64(0),
		sampledAt:          atomic.NewInt64(0),
		sampleWake:         make(chan struct{}, 1),
	}

	go DefaultManager.handle()
}

type Manager struct {
	connections        xsync.Map[string, Tracker]
	uploadTemp         atomic.Int64
	downloadTemp       atomic.Int64
	uploadBlip         atomic.Int64
	downloadBlip       atomic.Int64
	uploadTotal        atomic.Int64
	downloadTotal      atomic.Int64
	proxyUploadTemp    atomic.Int64
	proxyDownloadTemp  atomic.Int64
	proxyUploadBlip    atomic.Int64
	proxyDownloadBlip  atomic.Int64
	proxyUploadTotal   atomic.Int64
	proxyDownloadTotal atomic.Int64
	directUploadTotal   atomic.Int64
	directDownloadTotal atomic.Int64
	rejectUploadTotal   atomic.Int64
	rejectDownloadTotal atomic.Int64
	opened              atomic.Int64
	active              atomic.Int64
	rejected            atomic.Int64
	pid                 int32
	memory              atomic.Uint64

	lastReadAt atomic.Int64
	sampledAt  atomic.Int64
	sampleWake chan struct{}

	connectionObserver syncatomic.Pointer[func(joined bool, c Tracker)]
}

func (m *Manager) SetConnectionObserver(observe func(joined bool, c Tracker)) {
	if observe == nil {
		m.connectionObserver.Store(nil)
		return
	}
	m.connectionObserver.Store(&observe)
}

func (m *Manager) Join(c Tracker) {
	m.connections.Store(c.ID(), c)
	if observe := m.connectionObserver.Load(); observe != nil {
		(*observe)(true, c)
	}
}

func (m *Manager) Leave(c Tracker) {
	if _, present := m.connections.LoadAndDelete(c.ID()); present {
		m.noteLeave()
		if observe := m.connectionObserver.Load(); observe != nil {
			(*observe)(false, c)
		}
	}
}

func (m *Manager) Get(id string) (c Tracker) {
	if value, ok := m.connections.Load(id); ok {
		c = value
	}
	return
}

func (m *Manager) Range(f func(c Tracker) bool) {
	m.connections.Range(func(key string, value Tracker) bool {
		return f(value)
	})
}

type OutboundBucket uint8

const (
	BucketProxy OutboundBucket = iota
	BucketDirect
	BucketReject
)

var reservedOutboundBuckets = map[string]OutboundBucket{
	"DIRECT":      BucketDirect,
	"COMPATIBLE":  BucketDirect,
	"PASS":        BucketDirect,
	"REJECT":      BucketReject,
	"REJECT-DROP": BucketReject,
}

func BucketForOutbound(finalOutbound string) OutboundBucket {
	if bucket, reserved := reservedOutboundBuckets[finalOutbound]; reserved {
		return bucket
	}
	return BucketProxy
}

func isProxyOutbound(finalOutbound string) bool {
	return BucketForOutbound(finalOutbound) == BucketProxy
}

func (m *Manager) PushUploaded(finalOutbound string, size int64) {
	m.pushUploaded(BucketForOutbound(finalOutbound), size)
}

func (m *Manager) PushDownloaded(finalOutbound string, size int64) {
	m.pushDownloaded(BucketForOutbound(finalOutbound), size)
}

func (m *Manager) pushUploaded(bucket OutboundBucket, size int64) {
	switch bucket {
	case BucketProxy:
		m.proxyUploadTemp.Add(size)
		m.proxyUploadTotal.Add(size)
	case BucketDirect:
		m.directUploadTotal.Add(size)
	case BucketReject:
		m.rejectUploadTotal.Add(size)
	}
	m.uploadTemp.Add(size)
	m.uploadTotal.Add(size)
}

func (m *Manager) pushDownloaded(bucket OutboundBucket, size int64) {
	switch bucket {
	case BucketProxy:
		m.proxyDownloadTemp.Add(size)
		m.proxyDownloadTotal.Add(size)
	case BucketDirect:
		m.directDownloadTotal.Add(size)
	case BucketReject:
		m.rejectDownloadTotal.Add(size)
	}
	m.downloadTemp.Add(size)
	m.downloadTotal.Add(size)
}

type BucketTotal struct {
	Up   int64
	Down int64
}

type OutboundTotals struct {
	Proxy    BucketTotal
	Direct   BucketTotal
	Reject   BucketTotal
	Opened   int64
	Active   int64
	Rejected int64
}

func (m *Manager) OutboundTotals() OutboundTotals {
	return OutboundTotals{
		Proxy:    BucketTotal{Up: m.proxyUploadTotal.Load(), Down: m.proxyDownloadTotal.Load()},
		Direct:   BucketTotal{Up: m.directUploadTotal.Load(), Down: m.directDownloadTotal.Load()},
		Reject:   BucketTotal{Up: m.rejectUploadTotal.Load(), Down: m.rejectDownloadTotal.Load()},
		Opened:   m.opened.Load(),
		Active:   m.active.Load(),
		Rejected: m.rejected.Load(),
	}
}

func (m *Manager) noteJoin(bucket OutboundBucket) {
	m.opened.Add(1)
	m.active.Add(1)
	if bucket == BucketReject {
		m.rejected.Add(1)
	}
}

func (m *Manager) noteLeave() {
	m.active.Add(-1)
}

func (m *Manager) Now() (up int64, down int64) {
	fresh := m.rateFresh()
	m.noteRateRead()
	if !fresh {
		return 0, 0
	}
	return m.uploadBlip.Load(), m.downloadBlip.Load()
}

const RateFreshFor = 2 * time.Second

func (m *Manager) rateFresh() bool {
	at := m.sampledAt.Load()
	return at != 0 && monoNow()-at <= int64(RateFreshFor)
}

var monoBase = time.Now()

func monoNow() int64 {
	if elapsed := int64(time.Since(monoBase)); elapsed > 0 {
		return elapsed
	}
	return 1
}

func (m *Manager) LastRate() (up, down int64, sampledAt time.Time, fresh bool) {
	at := m.sampledAt.Load()
	if at != 0 {
		sampledAt = monoBase.Add(time.Duration(at))
	}
	return m.uploadBlip.Load(), m.downloadBlip.Load(), sampledAt, at != 0 && monoNow()-at <= int64(RateFreshFor)
}

func (m *Manager) Total() (up, down int64) {
	return m.uploadTotal.Load(), m.downloadTotal.Load()
}

func (m *Manager) NowTraffic(onlyProxy bool) (up, down int64) {
	if onlyProxy {
		fresh := m.rateFresh()
		m.noteRateRead()
		if !fresh {
			return 0, 0
		}
		return m.proxyUploadBlip.Load(), m.proxyDownloadBlip.Load()
	}
	return m.Now()
}

func (m *Manager) TotalTraffic(onlyProxy bool) (up, down int64) {
	if onlyProxy {
		return m.proxyUploadTotal.Load(), m.proxyDownloadTotal.Load()
	}
	return m.Total()
}

func (m *Manager) Memory() uint64 {
	m.updateMemory()
	return m.memory.Load()
}

func (m *Manager) Snapshot() *Snapshot {
	var connections []*TrackerInfo
	m.Range(func(c Tracker) bool {
		connections = append(connections, c.Info())
		return true
	})
	return &Snapshot{
		UploadTotal:   m.uploadTotal.Load(),
		DownloadTotal: m.downloadTotal.Load(),
		Connections:   connections,
		Memory:        m.memory.Load(),
	}
}

func (m *Manager) updateMemory() {
	stat, err := memory.GetMemoryInfo(m.pid)
	if err != nil {
		return
	}
	m.memory.Store(stat.RSS)
}

func (m *Manager) ResetStatistic() {
	m.uploadTemp.Store(0)
	m.uploadBlip.Store(0)
	m.uploadTotal.Store(0)
	m.downloadTemp.Store(0)
	m.downloadBlip.Store(0)
	m.downloadTotal.Store(0)
	m.proxyUploadTemp.Store(0)
	m.proxyUploadBlip.Store(0)
	m.proxyUploadTotal.Store(0)
	m.proxyDownloadTemp.Store(0)
	m.proxyDownloadBlip.Store(0)
	m.proxyDownloadTotal.Store(0)
}

const sampleIdleTimeout = 5 * time.Second

func (m *Manager) handle() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		if m.sampleIdle() {
			ticker.Stop()
			<-m.sampleWake
			m.uploadTemp.Store(0)
			m.downloadTemp.Store(0)
			m.proxyUploadTemp.Store(0)
			m.proxyDownloadTemp.Store(0)
			ticker.Reset(time.Second)
			continue
		}

		select {
		case <-ticker.C:
		case <-m.sampleWake:
			continue
		}

		m.uploadBlip.Store(m.uploadTemp.Swap(0))
		m.downloadBlip.Store(m.downloadTemp.Swap(0))
		m.proxyUploadBlip.Store(m.proxyUploadTemp.Swap(0))
		m.proxyDownloadBlip.Store(m.proxyDownloadTemp.Swap(0))
		m.sampledAt.Store(monoNow())
	}
}

func (m *Manager) sampleIdle() bool {
	last := m.lastReadAt.Load()
	if last == 0 {
		return true
	}
	return monoNow()-last > int64(sampleIdleTimeout)
}

func (m *Manager) noteRateRead() {
	m.lastReadAt.Store(monoNow())
	select {
	case m.sampleWake <- struct{}{}:
	default:
	}
}

type Snapshot struct {
	DownloadTotal int64          `json:"downloadTotal"`
	UploadTotal   int64          `json:"uploadTotal"`
	Connections   []*TrackerInfo `json:"connections"`
	Memory        uint64         `json:"memory"`
}
