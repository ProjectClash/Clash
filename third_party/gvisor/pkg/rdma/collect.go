// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package rdma

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

type UverbsSpec struct {
	Name string
	Major int64
	Minor int64
}

var pciAttrNames = []string{
	"class", "vendor", "device", "subsystem_vendor", "subsystem_device",
	"revision", "numa_node", "local_cpus", "local_cpulist",
	"max_link_speed", "max_link_width", "current_link_speed",
	"current_link_width", "modalias", "uevent",
}

var ibAttrNames = []string{
	"node_type", "node_guid", "sys_image_guid", "fw_ver", "board_id",
	"hca_type", "hw_rev", "node_desc",
}

var portLiveAttrNames = []string{
	"state", "phys_state", "rate", "lid", "sm_lid", "sm_sl",
}

var portStaticAttrNames = []string{"link_layer", "cap_mask"}

var netAttrNames = []string{
	"address", "addr_len", "type", "dev_id", "dev_port", "mtu", "speed",
	"duplex", "operstate", "carrier", "ifindex",
}

var numaAggregateNames = []string{
	"online", "possible", "has_cpu", "has_memory", "has_normal_memory",
}

var gpuClassPrefixes = []string{"0x0302", "0x0300", "0x0680"}

func Collect(sysRoot string, uverbs []UverbsSpec) (*Snapshot, error) {
	if len(uverbs) == 0 {
		return nil, nil
	}
	abi, err := mustReadAttr(path.Join(sysRoot, "class/infiniband_verbs/abi_version"))
	if err != nil {
		return nil, fmt.Errorf("reading verbs abi_version: %w", err)
	}
	s := &Snapshot{VerbsABIVersion: abi}

	pciPaths := make(map[string]bool)

	for _, u := range uverbs {
		if !SafeName(u.Name) {
			return nil, fmt.Errorf("unsafe uverbs device name %q", u.Name)
		}
		uvDir := path.Join(sysRoot, "class/infiniband_verbs", u.Name)
		dev, err := mustReadAttr(path.Join(uvDir, "dev"))
		if err != nil {
			return nil, fmt.Errorf("uverbs device %q: reading dev: %w", u.Name, err)
		}
		if want := fmt.Sprintf("%d:%d", u.Major, u.Minor); strings.TrimSpace(dev) != want {
			return nil, fmt.Errorf("uverbs device %q: sysfs dev is %q but the "+
				"OCI spec says %q; the host may have renumbered devices since "+
				"the spec was built", u.Name, strings.TrimSpace(dev), want)
		}
		ibdevRaw, err := mustReadAttr(path.Join(uvDir, "ibdev"))
		if err != nil {
			return nil, fmt.Errorf("uverbs device %q: reading ibdev: %w", u.Name, err)
		}
		ibdev := strings.TrimSpace(ibdevRaw)
		if !SafeName(ibdev) {
			return nil, fmt.Errorf("uverbs device %q: unusable ibdev name %q", u.Name, ibdev)
		}
		ibDir := path.Join(sysRoot, "class/infiniband", ibdev)

		leaf, err := relRealpath(sysRoot, path.Join(ibDir, "device"))
		if err != nil {
			return nil, fmt.Errorf("resolving PCI device of %s: %w", ibdev, err)
		}
		if err := addWithAncestors(pciPaths, leaf); err != nil {
			return nil, fmt.Errorf("ibdev %s: %w", ibdev, err)
		}

		abiVersion, err := mustReadAttr(path.Join(uvDir, "abi_version"))
		if err != nil {
			return nil, fmt.Errorf("uverbs device %q: reading abi_version: %w", u.Name, err)
		}
		ibAttrs, err := readAttrs(ibDir, ibAttrNames)
		if err != nil {
			return nil, fmt.Errorf("ibdev %s: %w", ibdev, err)
		}
		d := Device{
			Uverbs:     u.Name,
			IBDev:      ibdev,
			LeafPCI:    leaf,
			Dev:        dev,
			ABIVersion: abiVersion,
			IBAttrs:    ibAttrs,
			Ports:      map[string]Port{},
		}
		if err := d.collectPorts(ibDir); err != nil {
			return nil, fmt.Errorf("ibdev %s: %w", ibdev, err)
		}
		if err := d.collectNetDevs(sysRoot, path.Join(ibDir, "device/net")); err != nil {
			return nil, fmt.Errorf("ibdev %s: %w", ibdev, err)
		}
		s.Devices = append(s.Devices, d)
	}

	gpus, err := gpuLeaves(sysRoot)
	if err != nil {
		return nil, err
	}
	for _, g := range gpus {
		if err := addWithAncestors(pciPaths, g); err != nil {
			return nil, err
		}
	}

	for p := range pciPaths {
		attrs, err := readAttrs(path.Join(sysRoot, p), pciAttrNames)
		if err != nil {
			return nil, fmt.Errorf("PCI node %q: %w", p, err)
		}
		s.PCINodes = append(s.PCINodes, PCINode{Path: p, Attrs: attrs})
	}
	sort.Slice(s.PCINodes, func(i, j int) bool { return s.PCINodes[i].Path < s.PCINodes[j].Path })

	numa, err := collectNUMA(sysRoot)
	if err != nil {
		return nil, err
	}
	s.NUMA = numa
	return s, nil
}

func addWithAncestors(set map[string]bool, leaf string) error {
	if !strings.HasPrefix(leaf, "devices/pci") {
		return fmt.Errorf("PCI path %q is not under devices/pci*", leaf)
	}
	p := leaf
	for {
		base := path.Base(p)
		if bdfRE.MatchString(base) {
			set[p] = true
			p = path.Dir(p)
			continue
		}
		if pciRootRE.MatchString(base) {
			set[p] = true
			return nil
		}
		return fmt.Errorf("unexpected component %q in PCI path %q", base, leaf)
	}
}

func (d *Device) collectPorts(ibDir string) error {
	portsDir := path.Join(ibDir, "ports")
	ents, err := os.ReadDir(portsDir)
	if err != nil {
		return fmt.Errorf("reading %q: %w", portsDir, err)
	}
	for _, e := range ents {
		num := e.Name()
		if !SafeName(num) {
			continue
		}
		pDir := path.Join(portsDir, num)
		staticAttrs, err := readAttrs(pDir, portStaticAttrNames)
		if err != nil {
			return fmt.Errorf("port %s: %w", num, err)
		}
		gids, err := listSafeNames(path.Join(pDir, "gids"))
		if err != nil {
			return fmt.Errorf("port %s: %w", num, err)
		}
		counters, err := listOptionalNames(path.Join(pDir, "counters"))
		if err != nil {
			return fmt.Errorf("port %s: %w", num, err)
		}
		hwCounters, err := listOptionalNames(path.Join(pDir, "hw_counters"))
		if err != nil {
			return fmt.Errorf("port %s: %w", num, err)
		}
		d.Ports[num] = Port{
			StaticAttrs:    staticAttrs,
			LiveAttrs:      append([]string{}, portLiveAttrNames...),
			GIDNames:       gids,
			CounterNames:   counters,
			HWCounterNames: hwCounters,
		}
	}
	if len(d.Ports) == 0 {
		return fmt.Errorf("no ports under %q", portsDir)
	}
	return nil
}

func (d *Device) collectNetDevs(sysRoot, netDir string) error {
	ents, err := os.ReadDir(netDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("reading %q: %w", netDir, err)
	}
	for _, e := range ents {
		name := e.Name()
		if !SafeName(name) {
			continue
		}
		attrs, err := readAttrs(path.Join(sysRoot, "class/net", name), netAttrNames)
		if err != nil {
			return err
		}
		d.NetDevs = append(d.NetDevs, NetDev{Name: name, Attrs: attrs})
	}
	sort.Slice(d.NetDevs, func(i, j int) bool { return d.NetDevs[i].Name < d.NetDevs[j].Name })
	return nil
}

func gpuLeaves(sysRoot string) ([]string, error) {
	busDir := path.Join(sysRoot, "bus/pci/devices")
	ents, err := os.ReadDir(busDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading %q: %w", busDir, err)
	}
	var leaves []string
	for _, e := range ents {
		class, present, err := readAttr(path.Join(busDir, e.Name(), "class"))
		if err != nil {
			return nil, fmt.Errorf("reading class of PCI device %q: %w", e.Name(), err)
		}
		if !present {
			continue
		}
		match := false
		for _, p := range gpuClassPrefixes {
			if strings.HasPrefix(strings.TrimSpace(class), p) {
				match = true
				break
			}
		}
		if !match {
			continue
		}
		leaf, err := relRealpath(sysRoot, path.Join(busDir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("resolving PCI path of GPU %q: %w", e.Name(), err)
		}
		leaves = append(leaves, leaf)
	}
	return leaves, nil
}

func collectNUMA(sysRoot string) (*NUMA, error) {
	nodeDir := path.Join(sysRoot, "devices/system/node")
	if _, err := os.Stat(nodeDir); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("statting %q: %w", nodeDir, err)
	}
	agg, err := readAttrs(nodeDir, numaAggregateNames)
	if err != nil {
		return nil, err
	}
	return &NUMA{Aggregate: agg}, nil
}

func relRealpath(sysRoot, p string) (string, error) {
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(sysRoot, r)
	if err != nil || strings.HasPrefix(rel, "..") {
		return "", fmt.Errorf("%q resolves outside %q", p, sysRoot)
	}
	return rel, nil
}

func readAttr(p string) (content string, present bool, err error) {
	b, err := os.ReadFile(p)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", false, nil
		}
		return "", false, err
	}
	return string(b), true, nil
}

func mustReadAttr(p string) (string, error) {
	content, present, err := readAttr(p)
	if err != nil {
		return "", err
	}
	if !present {
		return "", fmt.Errorf("required sysfs file %q is missing", p)
	}
	return content, nil
}

func readAttrs(dir string, names []string) (map[string]string, error) {
	m := make(map[string]string)
	for _, name := range names {
		p := path.Join(dir, name)
		content, present, err := readAttr(p)
		if err != nil {
			return nil, fmt.Errorf("reading %q: %w", p, err)
		}
		if present {
			m[name] = content
		}
	}
	return m, nil
}

func listSafeNames(dir string) ([]string, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading %q: %w", dir, err)
	}
	var names []string
	for _, e := range ents {
		if SafeName(e.Name()) {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

func listOptionalNames(dir string) ([]string, error) {
	names, err := listSafeNames(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	return names, err
}
