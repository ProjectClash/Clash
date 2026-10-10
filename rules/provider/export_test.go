package provider

import (
	"testing"

	"github.com/ProjectClash/Clash/common/utils"
	P "github.com/ProjectClash/Clash/constant/provider"
	"github.com/ProjectClash/Clash/rules/common"
)

func NewClassicalStrategyInIndexDirectory(parse common.ParseRuleFunc, directory string) *classicalStrategy {
	s := NewClassicalStrategy(parse)
	s.indexDirectory = directory
	return s
}

func UseTestTunnel(t *testing.T) {
	old := tunnel
	SetTunnel(publicationTunnel{utils.NewCallback[P.RuleProvider]()})
	t.Cleanup(func() { SetTunnel(old) })
}
