package clash

import (
	"encoding/json"
	"testing"

	"github.com/metacubex/http/httptest"
	gotun "github.com/sagernet/sing-tun"
)

func TestTheMemorySnapshotCarriesTheVirtualSizeAndTheKeptRegions(t *testing.T) {
	if MemoryFootprint() <= 0 {
		t.Skip("no footprint reading on this platform")
	}
	var (
		recorder         *httptest.ResponseRecorder
		regions, notKept = 0, uint64(0)
		bytes            int64
		stable           bool
	)
	for attempt := 0; attempt < 5 && !stable; attempt++ {
		r0, b0, p0 := gotun.GoRegionsKept()
		recorder = httptest.NewRecorder()
		serveMemorySnapshot(recorder, nil)
		regions, bytes, notKept = gotun.GoRegionsKept()
		stable = r0 == regions && b0 == bytes && p0 == notKept
	}
	if !stable {
		t.Skip("the go stack's region table kept changing while it was read")
	}
	var payload struct {
		Footprint uint64  `json:"footprint"`
		Virtual   *int64  `json:"virtual"`
		Regions   *int    `json:"goRegionsKept"`
		Bytes     *int64  `json:"goRegionsKeptBytes"`
		NotKept   *uint64 `json:"goRegionsNotKept"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v (body=%s)", err, recorder.Body.String())
	}
	if payload.Virtual == nil || payload.Regions == nil || payload.Bytes == nil || payload.NotKept == nil {
		t.Fatalf("a key is missing: %s", recorder.Body.String())
	}
	if *payload.Virtual < int64(payload.Footprint) {
		t.Fatalf("virtual size %d below the footprint %d", *payload.Virtual, payload.Footprint)
	}
	if *payload.Regions != regions || *payload.Bytes != bytes || *payload.NotKept != notKept {
		t.Fatalf("the snapshot says %d/%d/%d, the table %d/%d/%d", *payload.Regions, *payload.Bytes, *payload.NotKept, regions, bytes, notKept)
	}
}
