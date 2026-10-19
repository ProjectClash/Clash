package clash

func ConfigProjectionJSON(configContent, kind, packagesJSON string) (*StringBox, error) {
	out, err := recoverAppCall("ConfigProjectionJSON", func() (*StringBox, error) {
		doc, err := NewConfigDocument(configContent)
		if err != nil {
			return nil, err
		}
		defer doc.Close()
		return doc.ProjectionJSON(kind, packagesJSON)
	})
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	return out, nil
}
