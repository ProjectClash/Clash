package clash

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ProjectClash/Clash/common/utils"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dlclark/regexp2"

	"github.com/ProjectClash/Clash/adapter"
	"github.com/ProjectClash/Clash/adapter/outbound"
	"github.com/ProjectClash/Clash/adapter/outboundgroup"
	adapterprovider "github.com/ProjectClash/Clash/adapter/provider"
	"github.com/ProjectClash/Clash/common/clashsum"
	"github.com/ProjectClash/Clash/constant"
)

const nodeLibraryPrefix, nodeLibrarySuffix = "nodes-", ".library"

const nodeLibraryTemporaryPrefix = ".library-"

func clashPrivateKey(key string) bool { return strings.HasPrefix(key, "x-clash-") }

func dropWrittenNodeFields(root map[string]any) {
	delete(root, "x-clash-node-library")
	if groups, ok := root["proxy-groups"].([]any); ok {
		for _, group := range groups {
			if mapping, ok := group.(map[string]any); ok {
				delete(mapping, groupMembersField)
				delete(mapping, groupMemberGroupField)
			}
		}
	}
}

func publishedNodeLibraryHere(reference any) error {
	mapping, _ := reference.(map[string]any)
	path, _ := mapping["path"].(string)
	want, _ := mapping["sha256"].(string)
	if path == "" || want == "" {
		return errors.New("x-clash-node-library: a path and a SHA-256 are required")
	}
	sum, err := usedNodeLibrary(path)
	if err != nil || hex.EncodeToString(sum) != strings.ToLower(want) {
		return fmt.Errorf("x-clash-node-library: this is a published configuration whose node library is not here; publish its source instead")
	}
	return nil
}

func nodesOnlyInLibrary(root map[string]any, reference any) bool {
	if mapping, _ := reference.(map[string]any); mapping != nil {
		if _, placed := mapping["inline-at"]; placed {
			return true
		}
	}
	list, _ := root["proxies"].([]any)
	return len(list) == 0
}

func catalogProviderLibraries(root map[string]any, directory string, staged map[string]string) {
	providers, _ := root["proxy-providers"].(map[string]any)
	for name, raw := range providers {
		definition, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		path, _ := definition["path"].(string)
		if kind, _ := definition["type"].(string); !strings.EqualFold(kind, "file") || path == "" || strings.HasSuffix(path, providerRuntimeIndexStubSuffix) {
			continue
		}
		payload, err := readBoundedRegularFile(constant.Path.Resolve(path), int64(providerContentBytes()), "provider payload")
		if err != nil {
			continue
		}
		format, _ := definition["format"].(string)
		key := sha256.New()
		io.WriteString(key, nodeLibraryBuilder()+"\x00provider\x00"+name+"\x00"+format+"\x00"+providerSelectionKey(definition)+"\x00")
		key.Write(payload)
		base := nodeLibraryPrefix + "p" + hex.EncodeToString(key.Sum(nil)[:16])
		libraryPath, stubPath := filepath.Join(directory, base+nodeLibrarySuffix), filepath.Join(directory, base+providerRuntimeIndexStubSuffix)
		if _, err := usedNodeLibrary(libraryPath, stubPath); err == nil && regularFileExists(stubPath) {
		} else {
			content := proxyProviderRuntimeContent(format, payload)
			library, count, err := adapterprovider.ClashCompileProviderLibrary(name, definition, content)
			if err != nil {
				continue
			}
			if writeLibraryFile(libraryPath, library, true) != nil {
				continue
			}
			stub := adapterprovider.ClashNodeLibraryStub(filepath.Base(libraryPath), [sha256.Size]byte(library[len(library)-sha256.Size:]), count) + "\n"
			if writeLibraryFile(stubPath, []byte(stub), false) != nil {
				continue
			}
		}
		definition["path"] = stubPath
		delete(staged, name)
	}
}

func writeNodeLibrary(root map[string]any, directory string) error {
	list, _ := root["proxies"].([]any)
	if len(list) == 0 {
		return nil
	}
	key := sha256.New()
	key.Write([]byte(nodeLibraryBuilder()))
	var kept []any
	var keptAt []int
	var held []int
	for idx, item := range list {
		mapping, ok := item.(map[string]any)
		var config string
		var err error
		if ok && !outboundgroup.IsClashInternalProxy(mapping) {
			config, err = adapter.LibraryNodeConfig(mapping)
		} else if ok {
			err = adapter.ErrNotLibraryNode
		}
		if !ok || errors.Is(err, adapter.ErrNotLibraryNode) {
			kept, keptAt = append(kept, item), append(keptAt, idx)
			continue
		}
		var size [binary.MaxVarintLen64]byte
		key.Write(size[:binary.PutUvarint(size[:], uint64(len(config)))])
		io.WriteString(key, config)
		held = append(held, idx)
	}
	if len(held) == 0 {
		return nil
	}
	groups := computeIncludeAllGroups(root, list)
	for _, group := range groups {
		io.WriteString(key, "\x00group\x00"+group.name)
		for _, at := range group.members {
			var b [4]byte
			binary.LittleEndian.PutUint32(b[:], at)
			key.Write(b[:])
		}
	}
	path := filepath.Join(directory, nodeLibraryPrefix+hex.EncodeToString(key.Sum(nil)[:16])+nodeLibrarySuffix)
	sum, err := usedNodeLibrary(path)
	if err != nil {
		writer := outbound.NewNodeLibraryWriter("")
		for _, group := range groups {
			writer.AddGroup(group.name, group.members)
		}
		for _, idx := range held {
			built, config, err := adapter.BuildLibraryNode(list[idx].(map[string]any))
			if err != nil {
				return fmt.Errorf("proxy %d: %w", idx, err)
			}
			err = writer.Add(built, config)
			_ = built.Close()
			if err != nil {
				return err
			}
		}
		var buffer bytes.Buffer
		if err := writer.Write(&buffer); err != nil {
			return err
		}
		data := buffer.Bytes()
		sum = data[len(data)-sha256.Size:]
		if err := writeLibraryFile(path, data, true); err != nil {
			return fmt.Errorf("node library: %w", err)
		}
	}
	libraryIndex := make(map[string]int, len(held))
	for k, idx := range held {
		if name, ok := adapter.ClashMappingNodeName(list[idx].(map[string]any)); ok {
			libraryIndex[name] = k
		}
	}
	compactGroupMembers(root, libraryIndex)
	markComputedGroups(root, groups)
	reference := map[string]any{"path": path, "sha256": hex.EncodeToString(sum)}
	if defaulted := xhttpReuseDefaultedIn(list, held); defaulted != nil {
		reference["xhttp-reuse-defaulted"] = defaulted
	}
	if len(kept) > 0 {
		reference["inline-at"] = keptAt
		root["proxies"] = kept
	} else {
		delete(root, "proxies")
	}
	root["x-clash-node-library"] = reference
	return nil
}

var nodeLibraryBuilder = sync.OnceValue(func() string {
	builder := "CNL1\x00" + constant.Version + "\x00" + runtime.Version()
	executable, err := os.Executable()
	if err != nil {
		return builder + "\x00" + fmt.Sprintf("%p", &builder)
	}
	info, err := os.Stat(executable)
	if err != nil {
		return builder + "\x00" + fmt.Sprintf("%p", &builder)
	}
	return builder + "\x00" + executable + "\x00" + fmt.Sprint(info.Size(), info.ModTime().UnixNano())
})

func writeLibraryFile(path string, data []byte, summed bool) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), nodeLibraryTemporaryPrefix)
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err = file.Write(data); err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(file.Name(), path); err != nil {
		return err
	}
	if summed && len(data) >= sha256.Size {
		clashsum.ProveWritten(path, [sha256.Size]byte(data[len(data)-sha256.Size:]))
	}
	return nil
}

const catalogLibraryLifetime = 7 * 24 * time.Hour

const nodeLibraryGrace = 10 * time.Minute

var nodeLibraryFilesMu sync.Mutex

func usedNodeLibrary(path string, companions ...string) ([]byte, error) {
	nodeLibraryFilesMu.Lock()
	defer nodeLibraryFilesMu.Unlock()
	now := time.Now()
	marked := func(file string) bool {
		info, err := os.Stat(file)
		if err != nil {
			return false
		}
		since := now.Sub(info.ModTime())
		return since >= 0 && since < nodeLibraryMarkEvery
	}
	touch := !marked(path+clashsum.ProofSuffix) && !marked(path)
	whole, left, err := clashsum.Persist(path, touch)
	if err != nil {
		if errors.Is(err, clashsum.ErrNotWhole) {
			return nil, fmt.Errorf("node library: %s is damaged", path)
		}
		if errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		return nil, fmt.Errorf("node library: %s is not one", path)
	}
	sum := whole[:]
	if !left && touch {
		_ = os.Chtimes(path, now, now)
	}
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		if resolved, err := filepath.EvalSymlinks(path); err == nil {
			if _, left, err := clashsum.Persist(resolved, !marked(resolved+clashsum.ProofSuffix) && !marked(resolved)); err == nil && !left {
				_ = os.Chtimes(resolved, now, now)
			}
		}
	}
	for _, file := range companions {
		if !marked(file) {
			_ = os.Chtimes(file, now, now)
		}
	}
	return sum, nil
}

const nodeLibraryMarkEvery = time.Minute

func PruneNodeLibraries(directory, keep string) error {
	_, err := recoverAppCall("PruneNodeLibraries", func() (struct{}, error) {
		var keeps []string
		if keep != "" {
			keeps = append(keeps, keep)
		}
		return struct{}{}, pruneNodeLibraries(directory, keeps)
	})
	return bridgeSafeError(err)
}

func PruneNodeLibrariesKeeping(directory, keepJSON string) error {
	_, err := recoverAppCall("PruneNodeLibrariesKeeping", func() (struct{}, error) {
		var keeps []string
		if strings.TrimSpace(keepJSON) != "" {
			if err := json.Unmarshal([]byte(keepJSON), &keeps); err != nil {
				return struct{}{}, fmt.Errorf("clash: libraries to keep: %w", err)
			}
		}
		return struct{}{}, pruneNodeLibraries(directory, keeps)
	})
	return bridgeSafeError(err)
}

func pruneNodeLibraries(directory string, keeps []string) error {
	return pruneFiles(directory, keeps, func(name string) bool {
		if strings.HasPrefix(name, nodeLibraryTemporaryPrefix) {
			return true
		}
		return strings.HasPrefix(name, nodeLibraryPrefix) && (strings.HasSuffix(name, nodeLibrarySuffix) || strings.HasSuffix(name, providerRuntimeIndexStubSuffix))
	})
}

func pruneFiles(directory string, keeps []string, staleName func(name string) bool) error {
	resolved := func(path string) string {
		if real, err := filepath.EvalSymlinks(path); err == nil {
			return real
		}
		return filepath.Clean(path)
	}
	kept := make(map[string]bool, len(keeps))
	for _, keep := range keeps {
		kept[resolved(keep)] = true
	}
	realDirectory := resolved(directory)
	entries, err := os.ReadDir(directory)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		if main, isProof := strings.CutSuffix(name, clashsum.ProofSuffix); isProof && staleName(main) {
			if _, err := os.Lstat(filepath.Join(directory, main)); errors.Is(err, os.ErrNotExist) {
				if err := os.Remove(filepath.Join(directory, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
					return err
				}
			}
			continue
		}
		if strings.HasPrefix(name, clashsum.ProofTemporaryPrefix) {
			if err := removeUnusedNodeLibrary(filepath.Join(directory, name)); err != nil {
				return err
			}
			continue
		}
		if !staleName(name) || kept[resolved(filepath.Join(realDirectory, name))] {
			continue
		}
		if err := removeUnusedNodeLibrary(filepath.Join(directory, name)); err != nil {
			return err
		}
	}
	return nil
}

func removeUnusedNodeLibrary(path string) error {
	nodeLibraryFilesMu.Lock()
	defer nodeLibraryFilesMu.Unlock()
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	lifetime := nodeLibraryGrace
	if strings.HasPrefix(filepath.Base(path), nodeLibraryPrefix+"p") {
		lifetime = catalogLibraryLifetime
	}
	used := info.ModTime()
	if info.Mode()&os.ModeSymlink != 0 {
		if target, err := os.Stat(path); err == nil && target.ModTime().After(used) {
			used = target.ModTime()
		}
	}
	if proof, err := os.Lstat(path + clashsum.ProofSuffix); err == nil && proof.ModTime().After(used) {
		used = proof.ModTime()
	}
	if time.Since(used) < lifetime {
		return nil
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Remove(path + clashsum.ProofSuffix); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

const groupMembersField = "x-clash-members"

const groupMemberGroupField = "x-clash-member-group"

const groupMembersCompactAt = 32

func compactGroupMembers(root map[string]any, index map[string]int) {
	groups, _ := root["proxy-groups"].([]any)
	for _, item := range groups {
		group, ok := item.(map[string]any)
		if !ok {
			continue
		}
		names, ok := group["proxies"].([]any)
		if !ok || len(names) < groupMembersCompactAt {
			continue
		}
		var entries []any
		from, to := -1, -1
		var first any
		flush := func() {
			switch {
			case from < 0:
			case to-from == 1:
				entries = append(entries, first)
			default:
				entries = append(entries, map[string]any{"from": from, "to": to})
			}
			from, to = -1, -1
		}
		for _, entry := range names {
			name, isName := adapter.ClashNodeName(entry)
			if isName {
				entry = name
			}
			at, inLibrary := index[name]
			if !isName || !inLibrary {
				flush()
				entries = append(entries, entry)
				continue
			}
			if from >= 0 && at == to {
				to++
				continue
			}
			flush()
			from, to, first = at, at+1, entry
		}
		flush()
		delete(group, "proxies")
		group[groupMembersField] = entries
	}
}

const NodeLibraryUnavailablePrefix = "x-clash-node-library: the node library is not here"

type computedGroup struct {
	name    string
	mapping map[string]any
	members []uint32
}

func computeIncludeAllGroups(root map[string]any, list []any) []computedGroup {
	groups, _ := root["proxy-groups"].([]any)
	var names []string
	var internal map[string]bool
	var out []computedGroup
	for _, item := range groups {
		group, ok := item.(map[string]any)
		if !ok || !(truthy(group["include-all"]) || truthy(group["include-all-proxies"])) {
			continue
		}
		name, _ := group["name"].(string)
		filter, _ := group["filter"].(string)
		if name == "" || filter == "" {
			continue
		}
		var regs []*regexp2.Regexp
		compiled := true
		for _, part := range strings.Split(filter, "`") {
			reg, err := utils.SharedRegexp2(part)
			if err != nil {
				compiled = false
				break
			}
			regs = append(regs, reg)
		}
		if !compiled {
			continue
		}
		if names == nil {
			internal = map[string]bool{}
			for _, entry := range list {
				if mapping, ok := entry.(map[string]any); ok {
					if n, ok := adapter.ClashMappingNodeName(mapping); ok {
						names = append(names, n)
						if outboundgroup.IsClashInternalProxy(mapping) {
							internal[n] = true
						}
					}
				}
			}
			sort.Strings(names)
		}
		var members []uint32
		for at, n := range names {
			if internal[n] {
				continue
			}
			for _, reg := range regs {
				if matched, _ := reg.MatchString(n); matched {
					members = append(members, uint32(at))
				}
			}
		}
		if len(members) == 0 {
			continue
		}
		out = append(out, computedGroup{name: name, mapping: group, members: members})
	}
	return out
}

func markComputedGroups(root map[string]any, groups []computedGroup) {
	for _, group := range groups {
		mapping := group.mapping
		if truthy(mapping["include-all"]) {
			mapping["include-all-providers"] = true
		}
		delete(mapping, "include-all")
		delete(mapping, "include-all-proxies")
		mapping[groupMemberGroupField] = group.name
	}
}

func truthy(value any) bool {
	switch v := value.(type) {
	case bool:
		return v
	case string:
		parsed, err := strconv.ParseBool(v)
		return err == nil && parsed
	}
	return false
}
