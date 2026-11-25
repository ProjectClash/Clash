package clash

import (
	"encoding/json"

	"github.com/ProjectClash/Clash/hub/route"
	"github.com/ProjectClash/Clash/tunnel/statistic"
	"github.com/metacubex/chi"
	"github.com/metacubex/http"
)

func init() {
	route.SetMemoryFootprintReader(MemoryFootprint)
	route.Register(func(router chi.Router) {
		for _, prefix := range privateRoutePrefixes {
			router.Get(prefix+"/traffic", serveTrafficSnapshot)
			router.Get(prefix+"/memory", serveMemorySnapshot)
		}
	})
}

func serveTrafficSnapshot(writer http.ResponseWriter, _ *http.Request) {
	source := trafficRates
	_, _, _, current := source.LastRate()
	up, down := source.Now()
	fresh := int64(0)
	if current {
		fresh = 1
	}
	upTotal, downTotal := source.Total()
	writeSnapshotJSON(writer, struct {
		Up        int64 `json:"up"`
		Down      int64 `json:"down"`
		UpTotal   int64 `json:"upTotal"`
		DownTotal int64 `json:"downTotal"`
		RateFresh int64 `json:"rateFresh"`
	}{up, down, upTotal, downTotal, fresh})
}

func serveMemorySnapshot(writer http.ResponseWriter, _ *http.Request) {
	footprint := MemoryFootprint()
	if footprint > 0 {
		var virtual *int64
		if size := virtualSize(); size > 0 {
			virtual = &size
		}
		regions, kept, notKept := goStackRegionsKept()
		writeSnapshotJSON(writer, struct {
			Inuse              uint64 `json:"inuse"`
			OSLimit            uint64 `json:"oslimit"`
			Footprint          uint64 `json:"footprint"`
			Virtual            *int64 `json:"virtual,omitempty"`
			GoRegionsKept      int    `json:"goRegionsKept"`
			GoRegionsKeptBytes int64  `json:"goRegionsKeptBytes"`
			GoRegionsNotKept   uint64 `json:"goRegionsNotKept"`
		}{statistic.DefaultManager.Memory(), 0, uint64(footprint), virtual, regions, kept, notKept})
		return
	}
	writeSnapshotJSON(writer, struct {
		Inuse   uint64 `json:"inuse"`
		OSLimit uint64 `json:"oslimit"`
	}{statistic.DefaultManager.Memory(), 0})
}

func writeSnapshotJSON(writer http.ResponseWriter, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	if err := json.NewEncoder(writer).Encode(value); err != nil {
		http.Error(writer, "encode snapshot", http.StatusInternalServerError)
	}
}
