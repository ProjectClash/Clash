package clash

import (
	"fmt"
	"math"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"github.com/ProjectClash/Clash/config"
	C "github.com/ProjectClash/Clash/constant"
)

const (
	reloadAccepted      = "accepted"
	reloadRefusedMemory = "memory"
	reloadUnmeasured    = "unmeasured"

	reloadBuildCostSafetyFactor = 2.0

	providerPayloadCostFactor = 6.0
)

type reloadMemoryReading struct {
	AvailableBytes         int64
	FootprintBytes         int64
	BaselineBytes          int64
	CurrentProviderBytes   int64
	CandidateProviderBytes int64
	ZeroMeansExhausted     bool
}

var zeroHeadroomMeansExhausted = runtime.GOOS == "ios"

type reloadMemoryVerdict struct {
	Reason         string `json:"reason"`
	NeededBytes    int64  `json:"neededBytes,omitempty"`
	AvailableBytes int64  `json:"availableBytes,omitempty"`
	FootprintBytes int64  `json:"footprintBytes,omitempty"`
	AtUnix         int64  `json:"atUnix,omitempty"`
}

var (
	readAvailableMemoryForReload = availableMemory
	readFootprintForReload       = physFootprint
)

func judgeReloadMemory(reading reloadMemoryReading, currentLength, candidateLength int) reloadMemoryVerdict {
	verdict := reloadMemoryVerdict{
		Reason:         reloadUnmeasured,
		AvailableBytes: reading.AvailableBytes,
		FootprintBytes: reading.FootprintBytes,
		AtUnix:         time.Now().Unix(),
	}
	if reading.AvailableBytes == 0 && reading.ZeroMeansExhausted {
		verdict.Reason = reloadRefusedMemory
		verdict.NeededBytes = reading.FootprintBytes
		if verdict.NeededBytes <= 0 {
			verdict.NeededBytes = 1
		}
		return verdict
	}
	if reading.AvailableBytes <= 0 || reading.FootprintBytes <= 0 {
		return verdict
	}
	oneCore := reading.FootprintBytes
	if reading.BaselineBytes > 0 && reading.BaselineBytes < reading.FootprintBytes {
		oneCore = reading.FootprintBytes - reading.BaselineBytes
	}
	needed := float64(oneCore) * reloadBuildCostSafetyFactor
	if currentLength > 0 && candidateLength > currentLength {
		needed *= float64(candidateLength) / float64(currentLength)
	}
	if growth := reading.CandidateProviderBytes - reading.CurrentProviderBytes; growth > 0 {
		needed += float64(growth) * providerPayloadCostFactor
	}
	verdict.NeededBytes = int64(math.Ceil(needed))
	if verdict.NeededBytes > reading.AvailableBytes {
		verdict.Reason = reloadRefusedMemory
	} else {
		verdict.Reason = reloadAccepted
	}
	return verdict
}

func (s *BoxService) judgeReloadAgainstTheCeiling(candidate string) reloadMemoryVerdict {
	reading := reloadMemoryReading{
		AvailableBytes:     readAvailableMemoryForReload(),
		ZeroMeansExhausted: zeroHeadroomMeansExhausted,
	}
	if reading.AvailableBytes > 0 || (reading.AvailableBytes == 0 && reading.ZeroMeansExhausted) {
		debug.FreeOSMemory()
		reading.AvailableBytes = readAvailableMemoryForReload()
		reading.FootprintBytes = readFootprintForReload()
		reading.BaselineBytes = s.startFootprintBytes
		reading.CurrentProviderBytes = s.providerBytes
		reading.CandidateProviderBytes = providerPayloadBytes(candidate)
	}
	s.candidateProviderBytes = -1
	if reading.AvailableBytes > 0 || (reading.AvailableBytes == 0 && reading.ZeroMeansExhausted) {
		s.candidateProviderBytes = reading.CandidateProviderBytes
	}
	if reserved := providerBuildReserved.Load(); reserved > 0 && reading.AvailableBytes > 0 {
		reading.AvailableBytes -= reserved
		if reading.AvailableBytes <= 0 {
			reading.AvailableBytes = 1
		}
	}
	verdict := judgeReloadMemory(reading, s.configLength, len(candidate))
	s.reloadVerdict = verdict
	return verdict
}

func reloadMemoryRefusal(verdict reloadMemoryVerdict) error {
	const mebibyte = 1 << 20
	return fmt.Errorf("clash: reload refused (memory): need ~%d MiB, have %d MiB; restart the appex instead",
		(verdict.NeededBytes+mebibyte-1)/mebibyte, verdict.AvailableBytes/mebibyte)
}

func providerPayloadBytes(configContent string) int64 {
	raw, err := config.UnmarshalRawConfig([]byte(configContent))
	if err != nil {
		return 0
	}
	var total int64
	variants := func(provider map[string]any, key string) []string {
		if value, ok := provider[key].(string); ok {
			return []string{value}
		}
		var values []string
		for k, v := range provider {
			if strings.ToLower(k) == key {
				if value, ok := v.(string); ok {
					values = append(values, value)
				}
			}
		}
		return values
	}
	sizeOf := func(path string) int64 {
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
			return info.Size()
		}
		return 0
	}
	count := func(kind string, providers map[string]map[string]any) {
		for _, provider := range providers {
			var largest int64
			if paths := variants(provider, "path"); len(paths) > 0 {
				for _, path := range paths {
					if size := sizeOf(C.Path.Resolve(path)); size > largest {
						largest = size
					}
				}
			} else {
				for _, url := range variants(provider, "url") {
					if size := sizeOf(C.Path.GetPathByHash(kind, url)); size > largest {
						largest = size
					}
				}
			}
			total += largest
		}
	}
	count("proxies", raw.ProxyProvider)
	count("rules", raw.RuleProvider)
	return total
}
