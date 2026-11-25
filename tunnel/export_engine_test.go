package tunnel

import C "github.com/ProjectClash/Clash/constant"

func EngineMayTakeOnceNamedForTest(metadata *C.Metadata) bool {
	return engineMayTakeOnceNamed(metadata)
}

func SubRulesForTest() map[string][]C.Rule { return loadVersion().subRules }
