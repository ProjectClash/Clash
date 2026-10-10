//go:build !(darwin && cgo)

package clash

func libresolvResolvers() ([]string, error) { return nil, errRouteLookupUnsupported }
