package clash

import (
	"github.com/ProjectClash/Clash/config"
	"go.yaml.in/yaml/v3"
)

type configDecode struct {
	err error
	raw *config.RawConfig

	unwritten       unwrittenAppleDefaults
	deviations      map[string]any
	deviationErr    error
	providerSources providerPayloadSources
}

var configDecodeObserver func(*configDecode)

func decodeConfigText(content string) *configDecode {
	decoded := &configDecode{}
	read := false
	raw, err := config.ClashUnmarshalRawConfig([]byte(content), func(decode func(any) error) {
		read = true
		decoded.unwritten = probeUnwrittenAppleDefaultsWith(decode)
		decoded.deviations, decoded.deviationErr = deviationDocumentWith(decode)
	})
	if err != nil {
		return &configDecode{err: err}
	}
	if !read {
		decoded.unwritten = probeUnwrittenAppleDefaults([]byte(content))
		decoded.deviations, decoded.deviationErr = deviationDocumentWith(func(out any) error {
			return yaml.Unmarshal([]byte(content), out)
		})
	}
	decoded.raw = raw
	decoded.providerSources = providerPayloadSourcesOf(raw)
	if observer := configDecodeObserver; observer != nil {
		observer(decoded)
	}
	return decoded
}

func deviationDocumentWith(decode func(any) error) (map[string]any, error) {
	var root map[string]any
	if err := decode(&root); err != nil {
		return nil, err
	}
	return deviationDocumentOf(root), nil
}

func (decoded *configDecode) providerBytes() int64 {
	if decoded == nil || decoded.err != nil {
		return 0
	}
	return decoded.providerSources.bytes()
}

func (decoded *configDecode) deviationRows(policy appleRuntimePolicy) ([]configDeviation, error) {
	if decoded.deviationErr != nil {
		return nil, decoded.deviationErr
	}
	return configDeviationRows(decoded.deviations, policy), nil
}
