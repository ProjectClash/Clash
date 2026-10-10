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
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
)

const Path = "/var/lib/gvisor/rdma_sysfs.json"

type PCINode struct {
	Path string `json:"path"`
	Attrs map[string]string `json:"attrs"`
}

type Port struct {
	StaticAttrs map[string]string `json:"static_attrs"`
	LiveAttrs   []string          `json:"live_attrs"`
	GIDNames       []string `json:"gid_names"`
	CounterNames   []string `json:"counter_names"`
	HWCounterNames []string `json:"hw_counter_names"`
}

type NetDev struct {
	Name  string            `json:"name"`
	Attrs map[string]string `json:"attrs"`
}

type Device struct {
	Uverbs string `json:"uverbs"`
	IBDev string `json:"ibdev"`
	LeafPCI string `json:"leaf_pci"`
	Dev        string `json:"dev"`
	ABIVersion string `json:"abi_version"`
	IBAttrs map[string]string `json:"ib_attrs"`
	Ports map[string]Port `json:"ports"`
	NetDevs []NetDev `json:"netdevs"`
}

type NUMA struct {
	Aggregate map[string]string `json:"aggregate"`
}

type Snapshot struct {
	VerbsABIVersion string `json:"verbs_abi_version"`
	PCINodes []PCINode `json:"pci_nodes"`
	Devices  []Device  `json:"devices"`
	NUMA     *NUMA     `json:"numa,omitempty"`
}

var safeName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:+-]*$`)

func SafeName(name string) bool {
	return safeName.MatchString(name)
}

var bdfRE = regexp.MustCompile(`^[0-9a-f]{4,}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]$`)

var pciRootRE = regexp.MustCompile(`^pci[0-9a-f]{4,}:[0-9a-f]{2}$`)

func IsBDF(name string) bool { return bdfRE.MatchString(name) }

func (s *Snapshot) Save(dst string) error {
	dir := filepath.Dir(dst)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("creating %q: %w", dir, err)
	}
	b, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("marshaling RDMA sysfs snapshot: %w", err)
	}
	return os.WriteFile(dst, b, 0644)
}

func Load(src string) (*Snapshot, error) {
	b, err := os.ReadFile(src)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var s Snapshot
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("unmarshaling RDMA sysfs snapshot %q: %w", src, err)
	}
	return &s, nil
}
