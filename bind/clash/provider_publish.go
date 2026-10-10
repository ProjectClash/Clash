package clash

import (
	"errors"
	"fmt"

	"github.com/ProjectClash/Clash/config"
	"github.com/ProjectClash/Clash/log"
)

func StageProvidersForPublish(configContent string, targetProfile string, compileRuleSets bool) error {
	return bridgeSafeError(recoverAppCallError("StageProvidersForPublish", func() error { return stageProvidersForPublishUnguarded(configContent, targetProfile, compileRuleSets) }))
}

func stageProvidersForPublishUnguarded(configContent string, targetProfile string, compileRuleSets bool) error {
	appParseMu.Lock()
	defer appParseMu.Unlock()
	profile, err := normalizeRuntimeProfile(targetProfile)
	if err != nil {
		return bridgeSafeError(err)
	}
	raw, err := config.UnmarshalRawConfig([]byte(configContent))
	if err != nil {
		return bridgeSafeError(fmt.Errorf("clash: parse config: %w", err))
	}
	canonicalizeProviderDefinitionKeys(raw)
	policy := runtimePolicyFor(profile, true)
	normalizeRawConfigForApple(raw, policy)
	runtime, err := stageProviderRuntime(raw, policy, compileRuleSets)
	if err != nil {
		return bridgeSafeError(err)
	}
	verdicts := providerVerdictCounts{}
	if runtime != nil {
		private := runtime.private
		verdicts = runtime.verdicts
		runtime.close()
		if private {
			return bridgeSafeError(classify(CoreOutcomeUnknown, errors.New("clash: provider staging is busy; nothing was published, retry")))
		}
	}
	log.Infoln("[Apple] provider publish staged into %s: compiled=%d indexed=%d notCompilable=%d keptSource=%d",
		stagedProviderParentDirectory(), verdicts.compiled, verdicts.indexed, verdicts.notCompilable, verdicts.keptSource)
	return nil
}

func DiscardPublishedProviderStaging() {
	parent := stagedProviderParentDirectory()
	unlock, locked := lockStagedProviderRuntime(parent)
	defer unlock()
	if !locked {
		log.Warnln("[Apple] provider staging is busy; the published staging was not discarded")
		return
	}
	manifest := &stagedProviderManifest{Entries: map[string]stagedProviderRecord{}}
	saveStagedProviderManifest(parent, manifest)
	sweepStagedProviderRuntime(parent, stagedProviderDirectory(), map[string]struct{}{})
	log.Infoln("[Apple] published provider staging discarded; the next start will stage from source")
}
