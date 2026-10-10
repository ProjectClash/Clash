package clash

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	C "github.com/ProjectClash/Clash/constant"
	P "github.com/ProjectClash/Clash/constant/provider"
	"github.com/ProjectClash/Clash/rules/provider"
)

type RuleProviderCompileResult struct {
	Compiled bool
	Behavior string
	Rules    int
	Reason   string
}

func CompileRuleProvider(sourcePath, behavior, format, outputPath string) (*RuleProviderCompileResult, error) {
	out, err := recoverAppCall("CompileRuleProvider", func() (*RuleProviderCompileResult, error) {
		return compileRuleProviderUnguarded(sourcePath, behavior, format, outputPath)
	})
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	return out, nil
}

func compileRuleProviderUnguarded(sourcePath, behavior, format, outputPath string) (*RuleProviderCompileResult, error) {
	home := C.Path.HomeDir()
	if !providerSourceContained(sourcePath, home) {
		return nil, bridgeSafeError(errors.New("clash: rule provider source is outside this app's container"))
	}
	if !providerSourceContained(outputPath, home) {
		return nil, bridgeSafeError(errors.New("clash: compiled rule provider destination is outside this app's container"))
	}
	source, err := readBoundedRegularFile(sourcePath, int64(maximumProviderResourceBytes), "rule provider")
	if err != nil {
		return nil, bridgeSafeError(fmt.Errorf("clash: read rule provider: %w", err))
	}
	result := compileRuleProviderPayload(source, behavior, format)
	if result.Reason != "" {
		return &RuleProviderCompileResult{Reason: result.Reason}, nil
	}
	if err := writeRuntimeProviderFile(outputPath, result.artifact); err != nil {
		return nil, bridgeSafeError(fmt.Errorf("clash: write compiled rule provider: %w", err))
	}
	return &RuleProviderCompileResult{
		Compiled: true,
		Behavior: result.Behavior,
		Rules:    result.Rules,
	}, nil
}

type ruleProviderCompilation struct {
	artifact []byte
	Behavior string
	Rules    int
	Reason   string
}

func compileRuleProviderPayload(source []byte, behavior, format string) ruleProviderCompilation {
	normalizedFormat := strings.ToLower(strings.TrimSpace(format))
	if normalizedFormat == "mrs" {
		return ruleProviderCompilation{Reason: "already compiled"}
	}

	targetBehavior := strings.ToLower(strings.TrimSpace(behavior))
	payload := source
	switch targetBehavior {
	case "domain", "ipcidr":
	case "classical":
		domains, reason := domainsFromClassical(source)
		if reason != "" {
			return ruleProviderCompilation{Reason: reason}
		}
		payload = []byte(strings.Join(domains, "\n") + "\n")
		targetBehavior = "domain"
		normalizedFormat = "text"
	default:
		return ruleProviderCompilation{Reason: fmt.Sprintf("unknown behavior %q", behavior)}
	}

	parsedBehavior, err := ruleBehavior(targetBehavior)
	if err != nil {
		return ruleProviderCompilation{Reason: err.Error()}
	}
	parsedFormat, err := ruleFormat(normalizedFormat)
	if err != nil {
		return ruleProviderCompilation{Reason: err.Error()}
	}

	var compiled bytes.Buffer
	if err := provider.ConvertToMrs(
		payload, parsedBehavior, parsedFormat, &compiled,
	); err != nil {
		return ruleProviderCompilation{Reason: fmt.Sprintf("cannot compile: %v", err)}
	}

	count, err := ProviderEntryCountForIOS("rule", targetBehavior, "mrs", compiled.Bytes())
	if err != nil {
		return ruleProviderCompilation{Reason: fmt.Sprintf("artifact unreadable: %v", err)}
	}

	return ruleProviderCompilation{
		artifact: compiled.Bytes(),
		Behavior: targetBehavior,
		Rules:    count,
	}
}

func domainsFromClassicalReason(source []byte) (int, string) {
	return classicalDomainScan(source, nil)
}

func domainsFromClassical(source []byte) ([]string, string) {
	var domains []string
	if _, reason := classicalDomainScan(source, func(domain string) {
		domains = append(domains, domain)
	}); reason != "" {
		return nil, reason
	}
	return domains, ""
}

func classicalDomainScan(source []byte, emit func(string)) (int, string) {
	count := 0
	for index, raw := range strings.Split(string(source), "\n") {
		lineNumber := index + 1
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		line = strings.TrimSpace(strings.TrimPrefix(line, "- "))
		line = strings.Trim(line, `'"`)
		if line == "" {
			continue
		}
		if line == "payload:" || line == "---" {
			continue
		}
		if i := strings.Index(line, " #"); i >= 0 {
			line = strings.TrimSpace(line[:i])
			if line == "" {
				continue
			}
		}
		kind, value, found := strings.Cut(line, ",")
		if !found {
			return count, fmt.Sprintf("line %d is not a classical rule (%d bytes)", lineNumber, len(line))
		}
		kind = strings.ToUpper(strings.TrimSpace(kind))
		value = strings.TrimSpace(value)
		if cut := strings.Index(value, ","); cut >= 0 {
			value = strings.TrimSpace(value[:cut])
		}
		switch kind {
		case "DOMAIN":
			if emit != nil {
				emit(value)
			}
			count++
		case "DOMAIN-SUFFIX":
			if emit != nil {
				emit("+." + value)
			}
			count++
		default:
			return count, fmt.Sprintf(
				"holds %s, which the domain strategy cannot store", kind,
			)
		}
	}
	if count == 0 {
		return 0, "no domain rules"
	}
	return count, ""
}

func ruleBehavior(name string) (P.RuleBehavior, error) {
	switch name {
	case "domain":
		return P.Domain, nil
	case "ipcidr":
		return P.IPCIDR, nil
	case "classical":
		return P.Classical, nil
	default:
		return P.Domain, fmt.Errorf("unknown behavior %q", name)
	}
}

func ruleFormat(name string) (P.RuleFormat, error) {
	switch name {
	case "", "yaml":
		return P.YamlRule, nil
	case "text":
		return P.TextRule, nil
	case "mrs":
		return P.MrsRule, nil
	default:
		return P.YamlRule, fmt.Errorf("unknown format %q", name)
	}
}
