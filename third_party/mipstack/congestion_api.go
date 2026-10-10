package mipstack

import (
	"fmt"
	"net/netip"
	"sort"
	"sync"
	"time"
)

const (
	CongestionControlCUBIC = "cubic"
	CongestionControlReno = "reno"
	CongestionControlBBR = "bbr"
	CongestionControlBBR3 = "bbr3"
)

type CongestionControlContext struct {
	LocalAddress netip.AddrPort
	RemoteAddress netip.AddrPort
	Passive bool
	Forwarded bool
}

type CongestionController interface {
	HandleCongestionEvent(event *CongestionEvent)
}

type CongestionControlFeatures uint32

const (
	CongestionControlFeatureDeliveryRate CongestionControlFeatures = 1 << iota
	CongestionControlFeatureCustomPacing
	CongestionControlFeatureTransmissionEvents
	CongestionControlFeatureCustomRecovery
	CongestionControlFeatureLossEvents
	CongestionControlFeatureCustomWindowValidation
)

const congestionControlKnownFeatures = CongestionControlFeatureDeliveryRate |
	CongestionControlFeatureCustomPacing |
	CongestionControlFeatureTransmissionEvents |
	CongestionControlFeatureCustomRecovery |
	CongestionControlFeatureLossEvents |
	CongestionControlFeatureCustomWindowValidation

type CongestionControlDefinition struct {
	Name string
	New func(CongestionControlContext) CongestionController
	Features CongestionControlFeatures
	SendBufferMultiplier uint32
}

type CongestionControlFactory struct {
	definition CongestionControlDefinition
}

func NewCongestionControlFactory(definition CongestionControlDefinition) (*CongestionControlFactory, error) {
	if err := validateCongestionControlDefinition(definition); err != nil {
		return nil, err
	}
	return &CongestionControlFactory{definition: definition}, nil
}

func (f *CongestionControlFactory) Name() string {
	if f == nil {
		return ""
	}
	return f.definition.Name
}

func (f *CongestionControlFactory) valid() bool {
	return f != nil && validateCongestionControlDefinition(f.definition) == nil
}

func validateCongestionControlDefinition(definition CongestionControlDefinition) error {
	if definition.Name == "" {
		return fmt.Errorf("mipstack: congestion control name is empty")
	}
	if definition.New == nil {
		return fmt.Errorf("mipstack: congestion control %q has no factory", definition.Name)
	}
	if unknown := definition.Features &^ congestionControlKnownFeatures; unknown != 0 {
		return fmt.Errorf("mipstack: congestion control %q has unknown features %#x", definition.Name, uint32(unknown))
	}
	if definition.Features&CongestionControlFeatureCustomPacing != 0 && definition.Features&CongestionControlFeatureTransmissionEvents == 0 {
		return fmt.Errorf("mipstack: congestion control %q custom pacing requires transmission events", definition.Name)
	}
	if definition.Features&CongestionControlFeatureLossEvents != 0 && definition.Features&CongestionControlFeatureTransmissionEvents == 0 {
		return fmt.Errorf("mipstack: congestion control %q loss events require transmission events", definition.Name)
	}
	if definition.Features&CongestionControlFeatureCustomWindowValidation != 0 && definition.Features&CongestionControlFeatureTransmissionEvents == 0 {
		return fmt.Errorf("mipstack: congestion control %q custom window validation requires transmission events", definition.Name)
	}
	return nil
}

var congestionControlRegistry = struct {
	sync.RWMutex
	factories map[string]*CongestionControlFactory
}{factories: map[string]*CongestionControlFactory{
	CongestionControlCUBIC: mustCongestionControlFactory(CongestionControlDefinition{
		Name:     CongestionControlCUBIC,
		New:      func(CongestionControlContext) CongestionController { return newCUBICCongestionControl() },
		Features: CongestionControlFeatureTransmissionEvents,
	}),
	CongestionControlReno: mustCongestionControlFactory(CongestionControlDefinition{
		Name: CongestionControlReno,
		New:  func(CongestionControlContext) CongestionController { return newRenoCongestionControl() },
	}),
	CongestionControlBBR: mustCongestionControlFactory(CongestionControlDefinition{
		Name: CongestionControlBBR,
		New:  func(CongestionControlContext) CongestionController { return newBBRCongestionControl() },
		Features: CongestionControlFeatureDeliveryRate |
			CongestionControlFeatureCustomPacing |
			CongestionControlFeatureTransmissionEvents |
			CongestionControlFeatureCustomRecovery |
			CongestionControlFeatureCustomWindowValidation,
		SendBufferMultiplier: 3,
	}),
	CongestionControlBBR3: mustCongestionControlFactory(CongestionControlDefinition{
		Name: CongestionControlBBR3,
		New:  func(CongestionControlContext) CongestionController { return newBBR3CongestionControl() },
		Features: CongestionControlFeatureDeliveryRate |
			CongestionControlFeatureCustomPacing |
			CongestionControlFeatureTransmissionEvents |
			CongestionControlFeatureCustomRecovery |
			CongestionControlFeatureLossEvents |
			CongestionControlFeatureCustomWindowValidation,
		SendBufferMultiplier: 3,
	}),
}}

func mustCongestionControlFactory(definition CongestionControlDefinition) *CongestionControlFactory {
	factory, err := NewCongestionControlFactory(definition)
	if err != nil {
		panic(err)
	}
	return factory
}

func RegisterCongestionControl(factory *CongestionControlFactory) error {
	if !factory.valid() {
		return fmt.Errorf("mipstack: invalid congestion control factory")
	}
	congestionControlRegistry.Lock()
	defer congestionControlRegistry.Unlock()
	name := factory.definition.Name
	if _, exists := congestionControlRegistry.factories[name]; exists {
		return fmt.Errorf("mipstack: congestion control %q is already registered", name)
	}
	congestionControlRegistry.factories[name] = factory
	return nil
}

func AvailableCongestionControls() []string {
	congestionControlRegistry.RLock()
	controls := make([]string, 0, len(congestionControlRegistry.factories))
	for name := range congestionControlRegistry.factories {
		controls = append(controls, name)
	}
	congestionControlRegistry.RUnlock()
	sort.Slice(controls, func(i, j int) bool { return controls[i] < controls[j] })
	return controls
}

func registeredCongestionControlFactory(name string) (*CongestionControlFactory, bool) {
	congestionControlRegistry.RLock()
	factory, exists := congestionControlRegistry.factories[name]
	congestionControlRegistry.RUnlock()
	return factory, exists
}

type CongestionEventType uint8

const (
	CongestionEventUnknown CongestionEventType = iota
	CongestionEventInitialize
	CongestionEventACK
	CongestionEventLoss
	CongestionEventECN
	CongestionEventTimeout
	CongestionEventPacketSent
	CongestionEventPacketRetransmitted
	CongestionEventRecovery
	CongestionEventStateChanged
	CongestionEventPacing
	CongestionEventMTUChanged
	CongestionEventDiagnostics
	CongestionEventPacketLost
	CongestionEventTailLossProbeRecovered
	CongestionEventRelease
)

type CongestionPhase uint8

const (
	CongestionPhaseUnknown CongestionPhase = iota
	CongestionPhaseOpen
	CongestionPhaseDisorder
	CongestionPhaseCWR
	CongestionPhaseRecovery
	CongestionPhaseLoss
)

type CongestionState struct {
	CongestionWindow uint32
	SlowStartThreshold uint32
	BytesInFlight uint32
	MaximumSegmentSize int
	SmoothedRTT time.Duration
	MinimumRTT time.Duration
	UsePacingRate bool
	PacingRate uint64
	MaximumPacingRate uint64
	DeliveredBytes uint64
	LostBytes uint64
	ApplicationLimited bool
	SchedulerLimited bool
	SchedulerLimitedEvents uint64
	Phase CongestionPhase
}

type CongestionRecoveryStage uint8

const (
	CongestionRecoveryUnknown CongestionRecoveryStage = iota
	CongestionRecoveryCheckpoint
	CongestionRecoverySelectFlight
	CongestionRecoveryEnter
	CongestionRecoveryPRR
	CongestionRecoveryExit
	CongestionRecoveryPartialACK
	CongestionRecoveryDuplicateACK
	CongestionRecoveryUndo
)

type CongestionRecovery struct {
	Stage CongestionRecoveryStage
	SACK bool
	OrdinaryFlight uint32
	LossFlight uint32
	Flight uint32
	PreviousWindow uint32
	Acknowledged uint32
	ProposedWindow uint32
}

type CongestionPacingOperation uint8

const (
	CongestionPacingUnknown CongestionPacingOperation = iota
	CongestionPacingQuery
	CongestionPacingWake
	CongestionPacingCancel
	CongestionPacingPolicyChanged
)

type CongestionPacing struct {
	Operation CongestionPacingOperation
	Bytes int
	TransmittedSegments uint64
	Delay time.Duration
	MarkSchedulerLimited bool
}

type CongestionDiagnostics struct {
	DeliveryRate uint64
	PacingRate uint64
	State string
	ApplicationLimited bool
	SchedulerLimited bool
	SchedulerLimitedEvents uint64
}

type CongestionEvent struct {
	Type CongestionEventType
	Time time.Time
	State *CongestionState
	Acknowledged uint32
	AcknowledgementNumber uint32
	SampleRTT time.Duration
	RateSample *CongestionRateSample
	PacketBytes int
	PacketState uint64
	OutstandingBytes uint32
	PreviousMaximumSegmentSize int
	PreviousPhase CongestionPhase
	MarkApplicationLimited bool
	Recovery CongestionRecovery
	Pacing CongestionPacing
	Diagnostics CongestionDiagnostics
}
