package provider

import "reflect"

func ClashRuleProviderSchemaType() reflect.Type { return reflect.TypeOf(ruleProviderSchema{}) }
