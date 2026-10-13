package provider

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/ProjectClash/Clash/adapter"
	"github.com/ProjectClash/Clash/adapter/outbound"
	"github.com/ProjectClash/Clash/common/structure"
	"github.com/ProjectClash/Clash/component/resource"
	C "github.com/ProjectClash/Clash/constant"
	P "github.com/ProjectClash/Clash/constant/provider"
)


const ClashNodeLibraryStubType = "CLASH-NODE-LIBRARY"

func ClashNodeLibraryStub(name string, sum [sha256.Size]byte, count int) string {
	return fmt.Sprintf("%s,%s,%s,%d", ClashNodeLibraryStubType, url.PathEscape(name), hex.EncodeToString(sum[:]), count)
}

func ClashProviderNodeMapping(mapping map[string]any, payload []byte, name string) (map[string]any, bool, error) {
	decoder := structure.NewDecoder(structure.Option{TagName: "provider", WeaklyTypedInput: true})
	schema := &proxyProviderSchema{HealthCheck: healthCheckSchema{Lazy: true}}
	if err := decoder.Decode(mapping, schema); err != nil {
		return nil, false, err
	}
	selectProxies, err := newProxiesSelector(schema.Filter, schema.ExcludeFilter, schema.ExcludeType, schema.DialerProxy, schema.Override, schema.AgeSecretKey)
	if err != nil {
		return nil, false, err
	}
	var found map[string]any
	err = selectProxies(payload, func(node map[string]any) error {
		if nodeName, ok := adapter.ClashMappingNodeName(node); ok && nodeName == name {
			found = node
			return errProviderNodeFound
		}
		return nil
	})
	if errors.Is(err, errProviderNodeFound) {
		return found, true, nil
	}
	return nil, false, err
}

var errProviderNodeFound = errors.New("found")

var ErrProviderNotLibrary = errors.New("the subscription's nodes cannot all go into a node library")

func ClashCompileProviderLibrary(name string, mapping map[string]any, payload []byte) ([]byte, int, error) {
	decoder := structure.NewDecoder(structure.Option{TagName: "provider", WeaklyTypedInput: true})
	schema := &proxyProviderSchema{HealthCheck: healthCheckSchema{Lazy: true}}
	if err := decoder.Decode(mapping, schema); err != nil {
		return nil, 0, err
	}
	selectProxies, err := newProxiesSelector(schema.Filter, schema.ExcludeFilter, schema.ExcludeType, schema.DialerProxy, schema.Override, schema.AgeSecretKey)
	if err != nil {
		return nil, 0, err
	}
	writer := outbound.NewNodeLibraryWriter(name)
	err = selectProxies(payload, func(node map[string]any) error {
		built, config, err := adapter.BuildLibraryNode(node, adapter.WithProviderName(name))
		if errors.Is(err, adapter.ErrNotLibraryNode) {
			return ErrProviderNotLibrary
		}
		if err != nil {
			return err
		}
		err = writer.Add(built, config)
		_ = built.Close()
		return err
	})
	if errors.Is(err, ErrProviderNotLibrary) {
		return nil, 0, ErrProviderNotLibrary
	}
	if err != nil {
		return nil, 0, err
	}
	var out bytes.Buffer
	if err := writer.Write(&out); err != nil {
		return nil, 0, err
	}
	return out.Bytes(), writer.Len(), nil
}

func clashProviderListParser(vehicle P.Vehicle, tunnel C.Tunnel, parser resource.Parser[[]C.Proxy]) resource.Parser[C.ProxyList] {
	return func(buf []byte) (C.ProxyList, error) {
		if directory := clashStubDirectory(vehicle); directory != "" {
			if path, sum, ok := parseNodeLibraryStub(buf, directory); ok {
				library, err := outbound.OpenNodeLibraryFile(path, sum)
				if err != nil {
					return nil, fmt.Errorf("node library %s: %w", filepath.Base(path), err)
				}
				return adapter.NewLibraryNodes(library, adapter.WithTunnelForAPI(tunnel)), nil
			}
		}
		proxies, err := parser(buf)
		if err != nil {
			return nil, err
		}
		return C.ProxySlice(proxies), nil
	}
}

func clashStubDirectory(vehicle P.Vehicle) string {
	if vehicle == nil || vehicle.Type() != P.File || !strings.HasSuffix(vehicle.Path(), ".stub") {
		return ""
	}
	if info, err := os.Lstat(vehicle.Path()); err != nil || !info.Mode().IsRegular() {
		return ""
	}
	return filepath.Dir(vehicle.Path())
}

func parseNodeLibraryStub(buf []byte, directory string) (string, [sha256.Size]byte, bool) {
	var sum [sha256.Size]byte
	line, _, _ := bufio.NewReader(bytes.NewReader(buf)).ReadLine()
	fields := strings.Split(strings.TrimSpace(string(line)), ",")
	if len(fields) != 4 || fields[0] != ClashNodeLibraryStubType || len(fields[2]) != 2*sha256.Size {
		return "", sum, false
	}
	name, err1 := url.PathUnescape(fields[1])
	digest, err2 := hex.DecodeString(fields[2])
	_, err3 := strconv.Atoi(fields[3])
	if err1 != nil || err2 != nil || err3 != nil || name == "" || name == "." || name == ".." ||
		strings.ContainsAny(name, `/\`) || filepath.Base(name) != name {
		return "", sum, false
	}
	return filepath.Join(directory, name), [sha256.Size]byte(digest), true
}
