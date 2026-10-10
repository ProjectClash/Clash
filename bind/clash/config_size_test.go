package clash

import (
	"encoding/json"
	"strings"
	"testing"
)

const formerConfigurationLimit = 4 * 1024 * 1024
const formerScriptJSONLimit = 16 * 1024 * 1024

func TestNoEntryPointRefusesAConfigurationForItsSize(t *testing.T) {
	if err := Setup(testOptions(t)); err != nil {
		t.Fatal(err)
	}
	large := "mode: rule\n#" + strings.Repeat("#", formerConfigurationLimit) + "\n"
	entryPoints := map[string]func() error{
		"parse": func() error {
			_, err := parseConfigForIOS(large, true)
			return err
		},
		"plan": func() error {
			_, err := PlanResourcesForIOS(large)
			return err
		},
		"finalize": func() error {
			_, err := FinalizeForIOS(large, "{}")
			return err
		},
		"merge": func() error {
			_, err := MergeOverrideForIOS(large, "")
			return err
		},
		"yaml-json": func() error {
			_, err := YamlToJSON(large)
			return err
		},
		"platform-intent": func() error {
			_, err := PlatformConfigIntentJSON(large)
			return err
		},
		"format": func() error {
			_, err := FormatConfig(large)
			return err
		},
		"check": func() error {
			return CheckConfig(large)
		},
		"deviations": func() error {
			_, err := ConfigDeviationsJSON(large, RuntimeProfileIOSPacketTunnel)
			return err
		},
		"invalid-domain-patterns": func() error {
			_, err := InvalidDomainPatternsJSON(large, "")
			return err
		},
	}
	for name, run := range entryPoints {
		t.Run(name, func(t *testing.T) {
			if err := run(); err != nil {
				t.Fatalf("a %d-byte configuration was refused: %v", len(large), err)
			}
		})
	}
}

func TestNoTransformRefusesItsOwnResultForItsSize(t *testing.T) {
	t.Run("script JSON in", func(t *testing.T) {
		input := strings.Repeat(" ", formerScriptJSONLimit+1) + "{}"
		if _, err := JSONToYaml(input); err != nil {
			t.Fatalf("a %d-byte script JSON was refused: %v", len(input), err)
		}
	})

	t.Run("script YAML out", func(t *testing.T) {
		input, err := json.Marshal(map[string]any{"payload": strings.Repeat("a", formerConfigurationLimit+1)})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := JSONToYaml(string(input)); err != nil {
			t.Fatalf("a YAML result past the former limit was refused: %v", err)
		}
	})

	t.Run("script JSON out", func(t *testing.T) {
		input := "payload: " + strings.Repeat("<", 3*1024*1024) + "\n"
		if _, err := YamlToJSON(input); err != nil {
			t.Fatalf("a JSON result past the former limit was refused: %v", err)
		}
	})

	t.Run("merged YAML out", func(t *testing.T) {
		raw := "base: " + strings.Repeat("a", 3*1024*1024) + "\n"
		override, err := json.Marshal(overrideSpec{Patch: map[string]any{
			"extra": strings.Repeat("b", 2*1024*1024),
		}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := MergeOverrideForIOS(raw, string(override)); err != nil {
			t.Fatalf("a merged result past the former limit was refused: %v", err)
		}
	})
}
