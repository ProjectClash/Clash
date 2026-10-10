package clash

import (
	"testing"

	"github.com/ProjectClash/Clash/component/geodata"
)

func resetGeodataFlagsForYardstick(t *testing.T) {
	t.Helper()
	geodata.SetCompiledGeoSiteOnly(false)
	geodata.SetCompiledGeoIPOnly(false)
	geodata.ClearGeoSiteCache()
	geodata.ClearGeoIPCache()
	resetGeoCountMemo()
}
