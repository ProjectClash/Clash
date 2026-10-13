package provider


import (
	"reflect"

	"go.yaml.in/yaml/v3"
)

var clashProxySchemaSequence = yaml.ClashSequence{Key: "proxies", Item: reflect.TypeOf(map[string]any(nil))}

func clashUnmarshalProxySchema(buf []byte, schema *ProxySchema) error {
	return yaml.ClashUnmarshal(buf, schema, clashProxySchemaSequence, nil)
}
