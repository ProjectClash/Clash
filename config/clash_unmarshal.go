package config


import (
	"fmt"
	"reflect"
	"strings"

	"github.com/ProjectClash/Clash/component/age"

	"go.yaml.in/yaml/v3"
)

var clashProxySequence = yaml.ClashSequence{Key: "proxies", Item: reflect.TypeOf(map[string]any(nil))}

func clashUnmarshal(buf []byte, out any, read func(decode func(out any) error)) error {
	return yaml.ClashUnmarshal(buf, out, clashProxySequence, read)
}

func ClashUnmarshalRawConfig(buf []byte, read func(decode func(out any) error)) (*RawConfig, error) {
	rawCfg := DefaultRawConfig()

	if strings.HasPrefix(string(buf), age.FileHeader) {
		read = nil
	}
	buf, err := age.DecryptBytes(buf)
	if err != nil {
		return nil, fmt.Errorf("decrypt config error: %w", err)
	}

	if err := clashUnmarshal(buf, rawCfg, read); err != nil {
		return nil, err
	}
	return rawCfg, nil
}
