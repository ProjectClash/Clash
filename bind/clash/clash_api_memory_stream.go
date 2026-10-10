package clash

import (
	"context"
	"encoding/json"
	"time"
)

const memoryFootprintFetchTimeout = time.Second

func (c *APIClient) enrichMemoryFrames(ctx context.Context, next func(string)) func(string) {
	return func(payload string) {
		if ctx.Err() != nil {
			return
		}
		object, valid := memoryPayloadObject(payload)
		if valid {
			if _, present := object["footprint"]; !present {
				payload = mergeFootprintIntoMemoryObject(payload, object, c.fetchSnapshotFootprint(ctx))
			}
		}
		if ctx.Err() == nil {
			next(payload)
		}
	}
}

func (c *APIClient) fetchSnapshotFootprint(parent context.Context) int64 {
	ctx, cancel := context.WithTimeout(parent, memoryFootprintFetchTimeout)
	defer cancel()
	payload, err := c.privateRequestWithContext(ctx, "GET", "/memory", nil)
	if err != nil {
		return 0
	}
	var snapshot struct {
		Footprint int64 `json:"footprint"`
	}
	if err := json.Unmarshal([]byte(payload), &snapshot); err != nil {
		return 0
	}
	return snapshot.Footprint
}

func memoryPayloadObject(payload string) (map[string]json.RawMessage, bool) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal([]byte(payload), &object); err != nil || object == nil {
		return nil, false
	}
	return object, true
}

func mergeFootprintIntoMemoryPayload(payload string, footprint int64) string {
	object, valid := memoryPayloadObject(payload)
	if !valid {
		return payload
	}
	return mergeFootprintIntoMemoryObject(payload, object, footprint)
}

func mergeFootprintIntoMemoryObject(payload string, object map[string]json.RawMessage, footprint int64) string {
	if footprint <= 0 || object == nil {
		return payload
	}
	if _, present := object["footprint"]; present {
		return payload
	}
	encoded, _ := json.Marshal(footprint)
	object["footprint"] = encoded
	merged, err := json.Marshal(object)
	if err != nil {
		return payload
	}
	return string(merged)
}
