package provider

import "reflect"

func ClashProviderSchemaType() reflect.Type { return reflect.TypeOf(proxyProviderSchema{}) }
