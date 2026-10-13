package sudoku

func ValidateTableSpec(mode string, customPattern string) error {
	asciiMode, err := ParseASCIIMode(mode)
	if err != nil {
		return err
	}
	if _, err = resolveLayout(asciiMode.uplinkPreference(), customPatternForToken(asciiMode.Uplink, customPattern)); err != nil {
		return err
	}
	if asciiMode.Uplink == asciiMode.Downlink {
		return nil
	}
	_, err = resolveLayout(asciiMode.downlinkPreference(), customPatternForToken(asciiMode.Downlink, customPattern))
	return err
}
