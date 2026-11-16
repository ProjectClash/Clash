package clash

import (
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"

	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/hub/route"
	"github.com/metacubex/chi"
	mhttp "github.com/metacubex/http"
)

// The App owns store/profiles.json and store/active.json in its working
// directory. These routes only read and rewrite the input fields the App
// consumes on its next connection; they never rebuild derived files.
const (
	appStoreDirectoryName = "store"
	appStoreProfilesFile  = "profiles.json"
	appStoreActiveFile    = "active.json"

	appStoreProfilesRoute         = "/app/profiles"
	appStoreProfileRulesRoute     = "/app/profiles/{id}/rules"
	appStoreProfileDNSPolicyRoute = "/app/profiles/{id}/dns-policy"

	appStoreRequestBodyBytes = 4 << 20

	appStoreMaximumAppendRules     = 5000
	appStoreMaximumRuleBytes       = 512
	appStoreMaximumDomainBytes     = 253
	appStoreMaximumNameserverBytes = 512
)

var (
	errAppStoreIndexMissing   = errors.New("the App has not published its profile index yet")
	errAppStoreProfileMissing = errors.New("no such App profile")
)

func init() {
	route.Register(func(router chi.Router) {
		for _, prefix := range privateRoutePrefixes {
			router.Get(prefix+appStoreProfilesRoute, serveAppProfiles)
			router.Get(prefix+appStoreProfileRulesRoute, serveAppProfileRules)
			router.Put(prefix+appStoreProfileRulesRoute, serveAppProfileRulesUpdate)
			router.Get(prefix+appStoreProfileDNSPolicyRoute, serveAppProfileDNSPolicy)
			router.Put(prefix+appStoreProfileDNSPolicyRoute, serveAppProfileDNSPolicyUpdate)
		}
	})
}

type appStoreActive struct {
	ProfileID string `json:"profileID"`
	Revision  string `json:"revision"`
}

type appStoreProfileSummary struct {
	ID             string `json:"id"`
	Label          string `json:"label"`
	Order          int    `json:"order"`
	ActiveRevision string `json:"activeRevision"`
	Active         bool   `json:"active"`
	AppendedRules  int    `json:"appendedRules"`
	PrependedRules bool   `json:"prependedRules"`
	Patched        bool   `json:"patched"`
}

type appStoreIndex struct {
	Active   appStoreActive           `json:"active"`
	Profiles []appStoreProfileSummary `json:"profiles"`
}

type appStoreRules struct {
	ID           string   `json:"id"`
	PrependRules bool     `json:"prependRules"`
	AppendRules  []string `json:"appendRules"`
	PatchJSON    string   `json:"patchJSON"`
}

type appStoreRulesUpdate struct {
	PrependRules *bool     `json:"prependRules"`
	AppendRules  *[]string `json:"appendRules"`
}

type appStoreDNSPolicy struct {
	NameserverPolicy map[string][]string `json:"nameserverPolicy"`
	FakeIPFilter     []string            `json:"fakeIPFilter"`
}

type appStoreDNSPolicyUpdate struct {
	NameserverPolicy *map[string][]string `json:"nameserverPolicy"`
	FakeIPFilter     *[]string            `json:"fakeIPFilter"`
}

func appStoreRoot() string {
	return filepath.Join(C.Path.HomeDir(), appStoreDirectoryName)
}

func appStoreGuard(writer mhttp.ResponseWriter, request *mhttp.Request) bool {
	if !overAppGroupSocket(request) && !route.RequestFromManagedListener(request) {
		mhttp.NotFound(writer, request)
		return false
	}
	return true
}

func serveAppProfiles(writer mhttp.ResponseWriter, request *mhttp.Request) {
	if !appStoreGuard(writer, request) {
		return
	}
	index, err := loadAppStoreIndexAt(appStoreRoot())
	if err != nil {
		appStoreRefusal(writer, err)
		return
	}
	writeControllerJSON(writer, index)
}

func serveAppProfileRules(writer mhttp.ResponseWriter, request *mhttp.Request) {
	if !appStoreGuard(writer, request) {
		return
	}
	rules, err := loadAppStoreRulesAt(appStoreRoot(), chi.URLParam(request, "id"))
	if err != nil {
		appStoreRefusal(writer, err)
		return
	}
	writeControllerJSON(writer, rules)
}

func serveAppProfileRulesUpdate(writer mhttp.ResponseWriter, request *mhttp.Request) {
	if !appStoreGuard(writer, request) {
		return
	}
	var update appStoreRulesUpdate
	if err := json.NewDecoder(io.LimitReader(request.Body, appStoreRequestBodyBytes)).Decode(&update); err != nil {
		mhttp.Error(writer, "invalid rules payload", mhttp.StatusBadRequest)
		return
	}
	if update.AppendRules != nil {
		if err := validateAppStoreRules(*update.AppendRules); err != nil {
			mhttp.Error(writer, err.Error(), mhttp.StatusBadRequest)
			return
		}
	}
	if err := saveAppStoreRulesAt(appStoreRoot(), chi.URLParam(request, "id"), update); err != nil {
		appStoreRefusal(writer, err)
		return
	}
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(mhttp.StatusNoContent)
}

func serveAppProfileDNSPolicy(writer mhttp.ResponseWriter, request *mhttp.Request) {
	if !appStoreGuard(writer, request) {
		return
	}
	policy, err := loadAppStoreDNSPolicyAt(appStoreRoot(), chi.URLParam(request, "id"))
	if err != nil {
		appStoreRefusal(writer, err)
		return
	}
	writeControllerJSON(writer, policy)
}

func serveAppProfileDNSPolicyUpdate(writer mhttp.ResponseWriter, request *mhttp.Request) {
	if !appStoreGuard(writer, request) {
		return
	}
	var update appStoreDNSPolicyUpdate
	if err := json.NewDecoder(io.LimitReader(request.Body, appStoreRequestBodyBytes)).Decode(&update); err != nil {
		mhttp.Error(writer, "invalid DNS policy payload", mhttp.StatusBadRequest)
		return
	}
	if update.NameserverPolicy != nil {
		if err := validateAppStoreNameserverPolicy(*update.NameserverPolicy); err != nil {
			mhttp.Error(writer, err.Error(), mhttp.StatusBadRequest)
			return
		}
	}
	if update.FakeIPFilter != nil {
		if err := validateAppStoreDomains(*update.FakeIPFilter); err != nil {
			mhttp.Error(writer, err.Error(), mhttp.StatusBadRequest)
			return
		}
	}
	if err := saveAppStoreDNSPolicyAt(appStoreRoot(), chi.URLParam(request, "id"), update); err != nil {
		appStoreRefusal(writer, err)
		return
	}
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(mhttp.StatusNoContent)
}

func appStoreRefusal(writer mhttp.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errAppStoreProfileMissing):
		mhttp.Error(writer, err.Error(), mhttp.StatusNotFound)
	case errors.Is(err, errAppStoreIndexMissing):
		mhttp.Error(writer, err.Error(), mhttp.StatusServiceUnavailable)
	default:
		mhttp.Error(writer, "the App's profile store cannot be read", mhttp.StatusInternalServerError)
	}
}

func loadAppStoreIndexAt(directory string) (appStoreIndex, error) {
	entries, err := readAppStoreProfilesAt(directory)
	if err != nil {
		return appStoreIndex{}, err
	}
	active, err := readAppStoreActiveAt(directory)
	if err != nil {
		return appStoreIndex{}, err
	}
	summaries := make([]appStoreProfileSummary, 0, len(entries))
	for _, entry := range entries {
		override := appStoreOverride(entry)
		var patchJSON string
		_ = json.Unmarshal(override["patchJSON"], &patchJSON)
		var appendRules []string
		_ = json.Unmarshal(override["appendRules"], &appendRules)
		var prependRules bool
		_ = json.Unmarshal(override["prependRules"], &prependRules)
		id := appStoreFieldString(entry, "id")
		summaries = append(summaries, appStoreProfileSummary{
			ID:             id,
			Label:          appStoreFieldString(entry, "label"),
			Order:          appStoreFieldInt(entry, "order"),
			ActiveRevision: appStoreFieldString(entry, "activeRevision"),
			Active:         id != "" && id == active.ProfileID,
			AppendedRules:  len(appendRules),
			PrependedRules: prependRules,
			Patched:        strings.TrimSpace(patchJSON) != "",
		})
	}
	sort.SliceStable(summaries, func(i, j int) bool {
		if summaries[i].Order != summaries[j].Order {
			return summaries[i].Order < summaries[j].Order
		}
		return summaries[i].Label < summaries[j].Label
	})
	return appStoreIndex{Active: active, Profiles: summaries}, nil
}

func loadAppStoreRulesAt(directory, id string) (appStoreRules, error) {
	entries, err := readAppStoreProfilesAt(directory)
	if err != nil {
		return appStoreRules{}, err
	}
	index := appStoreEntryIndex(entries, id)
	if index < 0 {
		return appStoreRules{}, errAppStoreProfileMissing
	}
	override := appStoreOverride(entries[index])
	rules := appStoreRules{ID: id, AppendRules: []string{}}
	_ = json.Unmarshal(override["prependRules"], &rules.PrependRules)
	_ = json.Unmarshal(override["appendRules"], &rules.AppendRules)
	_ = json.Unmarshal(override["patchJSON"], &rules.PatchJSON)
	if rules.AppendRules == nil {
		rules.AppendRules = []string{}
	}
	return rules, nil
}

// saveAppStoreRulesAt rewrites only override.appendRules and override.prependRules.
// Every other field, known or unknown, is carried over byte for byte.
func saveAppStoreRulesAt(directory, id string, update appStoreRulesUpdate) error {
	entries, err := readAppStoreProfilesAt(directory)
	if err != nil {
		return err
	}
	index := appStoreEntryIndex(entries, id)
	if index < 0 {
		return errAppStoreProfileMissing
	}
	entry := entries[index]
	override, err := appStoreOverrideObject(entry)
	if err != nil {
		return err
	}
	if update.AppendRules != nil {
		rules := *update.AppendRules
		if rules == nil {
			rules = []string{}
		}
		if err := assignAppStoreRaw(override, "appendRules", rules); err != nil {
			return err
		}
	}
	if update.PrependRules != nil {
		if err := assignAppStoreRaw(override, "prependRules", *update.PrependRules); err != nil {
			return err
		}
	}
	if err := assignAppStoreRaw(entry, "override", override); err != nil {
		return err
	}
	return writeAppStoreProfilesAt(directory, entries)
}

func loadAppStoreDNSPolicyAt(directory, id string) (appStoreDNSPolicy, error) {
	policy := appStoreDNSPolicy{NameserverPolicy: map[string][]string{}, FakeIPFilter: []string{}}
	patch, err := loadAppStoreRuntimePatchAt(directory, id)
	if err != nil {
		return appStoreDNSPolicy{}, err
	}
	dns := appStoreNestedObject(patch, "dns")
	_ = json.Unmarshal(dns["nameserver-policy"], &policy.NameserverPolicy)
	_ = json.Unmarshal(dns["fake-ip-filter"], &policy.FakeIPFilter)
	if policy.NameserverPolicy == nil {
		policy.NameserverPolicy = map[string][]string{}
	}
	if policy.FakeIPFilter == nil {
		policy.FakeIPFilter = []string{}
	}
	return policy, nil
}

// saveAppStoreDNSPolicyAt rewrites only the dns keys it was given inside
// legacyRuntimePatchJSON, keeping the rest of that patch and every other field.
func saveAppStoreDNSPolicyAt(directory, id string, update appStoreDNSPolicyUpdate) error {
	entries, err := readAppStoreProfilesAt(directory)
	if err != nil {
		return err
	}
	index := appStoreEntryIndex(entries, id)
	if index < 0 {
		return errAppStoreProfileMissing
	}
	entry := entries[index]
	patch, err := appStorePatchObject(entry)
	if err != nil {
		return err
	}
	dns := appStoreNestedObject(patch, "dns")
	if update.NameserverPolicy != nil {
		policy := *update.NameserverPolicy
		if policy == nil {
			policy = map[string][]string{}
		}
		if err := assignAppStoreRaw(dns, "nameserver-policy", policy); err != nil {
			return err
		}
	}
	if update.FakeIPFilter != nil {
		filter := *update.FakeIPFilter
		if filter == nil {
			filter = []string{}
		}
		if err := assignAppStoreRaw(dns, "fake-ip-filter", filter); err != nil {
			return err
		}
	}
	if err := assignAppStoreRaw(patch, "dns", dns); err != nil {
		return err
	}
	encoded, err := json.Marshal(patch)
	if err != nil {
		return err
	}
	if err := assignAppStoreRaw(entry, "legacyRuntimePatchJSON", string(encoded)); err != nil {
		return err
	}
	return writeAppStoreProfilesAt(directory, entries)
}

func loadAppStoreRuntimePatchAt(directory, id string) (map[string]json.RawMessage, error) {
	entries, err := readAppStoreProfilesAt(directory)
	if err != nil {
		return nil, err
	}
	index := appStoreEntryIndex(entries, id)
	if index < 0 {
		return nil, errAppStoreProfileMissing
	}
	return appStorePatchObject(entries[index])
}

func appStorePatchObject(entry map[string]json.RawMessage) (map[string]json.RawMessage, error) {
	patch := map[string]json.RawMessage{}
	var legacy string
	if raw, ok := entry["legacyRuntimePatchJSON"]; ok && string(raw) != "null" {
		if err := json.Unmarshal(raw, &legacy); err != nil {
			return nil, err
		}
	}
	if strings.TrimSpace(legacy) == "" {
		return patch, nil
	}
	if err := json.Unmarshal([]byte(legacy), &patch); err != nil {
		return nil, err
	}
	if patch == nil {
		patch = map[string]json.RawMessage{}
	}
	return patch, nil
}

func appStoreNestedObject(parent map[string]json.RawMessage, key string) map[string]json.RawMessage {
	nested := map[string]json.RawMessage{}
	if raw, ok := parent[key]; ok {
		if err := json.Unmarshal(raw, &nested); err != nil || nested == nil {
			nested = map[string]json.RawMessage{}
		} else {
			return nested
		}
	}
	parent[key] = json.RawMessage(`{}`)
	return nested
}

func assignAppStoreRaw(target map[string]json.RawMessage, key string, value any) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	target[key] = encoded
	return nil
}

func appStoreOverride(entry map[string]json.RawMessage) map[string]json.RawMessage {
	override, _ := appStoreOverrideObject(entry)
	return override
}

func appStoreOverrideObject(entry map[string]json.RawMessage) (map[string]json.RawMessage, error) {
	override := map[string]json.RawMessage{}
	if raw, ok := entry["override"]; ok && string(raw) != "null" {
		if err := json.Unmarshal(raw, &override); err != nil {
			return nil, err
		}
		if override == nil {
			override = map[string]json.RawMessage{}
		}
	}
	return override, nil
}

func appStoreEntryIndex(entries []map[string]json.RawMessage, id string) int {
	if id == "" {
		return -1
	}
	for i, entry := range entries {
		if appStoreFieldString(entry, "id") == id {
			return i
		}
	}
	return -1
}

func appStoreFieldString(entry map[string]json.RawMessage, key string) string {
	var value string
	_ = json.Unmarshal(entry[key], &value)
	return value
}

func appStoreFieldInt(entry map[string]json.RawMessage, key string) int {
	var value int
	_ = json.Unmarshal(entry[key], &value)
	return value
}

func readAppStoreProfilesAt(directory string) ([]map[string]json.RawMessage, error) {
	data, err := os.ReadFile(filepath.Join(directory, appStoreProfilesFile))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, errAppStoreIndexMissing
		}
		return nil, err
	}
	var entries []map[string]json.RawMessage
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, err
	}
	return entries, nil
}

func readAppStoreActiveAt(directory string) (appStoreActive, error) {
	var active appStoreActive
	data, err := os.ReadFile(filepath.Join(directory, appStoreActiveFile))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return active, nil
		}
		return active, err
	}
	if err := json.Unmarshal(data, &active); err != nil {
		return active, err
	}
	return active, nil
}

func writeAppStoreProfilesAt(directory string, entries []map[string]json.RawMessage) error {
	if entries == nil {
		entries = []map[string]json.RawMessage{}
	}
	// The App writes this index indented; matching it keeps the file readable
	// and the diff small when the App rewrites it after the next connection.
	payload, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}
	return writeAppStoreFileAtomically(filepath.Join(directory, appStoreProfilesFile), append(payload, '\n'))
}

func writeAppStoreFileAtomically(path string, payload []byte) error {
	directory := filepath.Dir(path)
	file, err := os.CreateTemp(directory, ".app-store-")
	if err != nil {
		return err
	}
	temporaryPath := file.Name()
	committed := false
	defer func() {
		_ = file.Close()
		if !committed {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	if _, err := file.Write(payload); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	committed = true
	return nil
}

func validateAppStoreRules(rules []string) error {
	if len(rules) > appStoreMaximumAppendRules {
		return errors.New("too many appended rules")
	}
	for _, rule := range rules {
		if len(rule) == 0 || len(rule) > appStoreMaximumRuleBytes {
			return errors.New("each appended rule must be 1..512 bytes")
		}
		if strings.ContainsAny(rule, "\n\r\x00") {
			return errors.New("an appended rule must not contain a line break or a NUL")
		}
	}
	return nil
}

func validateAppStoreNameserverPolicy(policy map[string][]string) error {
	for domain, servers := range policy {
		if err := validateAppStoreDomain(domain); err != nil {
			return err
		}
		for _, server := range servers {
			if err := validateAppStoreNameserver(server); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateAppStoreDomains(domains []string) error {
	for _, domain := range domains {
		if err := validateAppStoreDomain(domain); err != nil {
			return err
		}
	}
	return nil
}

func validateAppStoreDomain(domain string) error {
	if domain == "" || len(domain) > appStoreMaximumDomainBytes {
		return errors.New("each DNS policy domain must be 1..253 bytes")
	}
	if strings.ContainsAny(domain, "\n\r\x00") {
		return errors.New("a DNS policy domain must not contain a line break or a NUL")
	}
	return nil
}

var appStoreNameserverSchemes = []string{"https://", "tls://", "quic://", "h3://", "dhcp://"}

func validateAppStoreNameserver(server string) error {
	if len(server) == 0 || len(server) > appStoreMaximumNameserverBytes {
		return errors.New("each nameserver must be 1..512 bytes")
	}
	for _, candidate := range strings.Split(server, ",") {
		candidate = strings.TrimSpace(candidate)
		if validateAppStoreNameserverAddress(candidate) != nil {
			return errors.New("a nameserver must be an IP address or an https://, tls://, quic://, h3:// or dhcp:// address")
		}
	}
	return nil
}

func validateAppStoreNameserverAddress(address string) error {
	if address == "" {
		return errors.New("empty nameserver")
	}
	if net.ParseIP(address) != nil {
		return nil
	}
	for _, scheme := range appStoreNameserverSchemes {
		if strings.HasPrefix(address, scheme) && len(address) > len(scheme) {
			return nil
		}
	}
	return errors.New("unsupported nameserver address")
}
