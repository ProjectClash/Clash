package clash

func ConfigProjectionJSON(configContent, kind, packagesJSON string) (*StringBox, error) {
	doc, err := NewConfigDocument(configContent)
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	defer doc.Close()
	bridgedValue0, bridgedErr := doc.ProjectionJSON(kind, packagesJSON)
	return bridgedValue0, bridgeSafeError(bridgedErr)
}
