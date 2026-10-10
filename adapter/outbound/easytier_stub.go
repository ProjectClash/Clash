//go:build no_easytier

package outbound

import (
	"encoding/json"

	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/log"
)

type EasyTier struct {
	*Reject
}

type EasyTierOption struct {
	BasicOption
	Name                string   `proxy:"name"`
	NetworkName         string   `proxy:"network-name,omitempty"`
	NetworkSecret       string   `proxy:"network-secret,omitempty"`
	Hostname            string   `proxy:"hostname,omitempty"`
	IPv4                string   `proxy:"ipv4,omitempty"`
	DHCP                bool     `proxy:"dhcp,omitempty"`
	Peers               []string `proxy:"peers,omitempty"`
	Listeners           []string `proxy:"listeners,omitempty"`
	NoListener          *bool    `proxy:"no-listener,omitempty"`
	MappedListeners     []string `proxy:"mapped-listeners,omitempty"`
	ExitNodes           []string `proxy:"exit-nodes,omitempty"`
	ProxyNetworks       []string `proxy:"proxy-networks,omitempty"`
	InstanceName        string   `proxy:"instance-name,omitempty"`
	StateDir            string   `proxy:"state-dir,omitempty"`
	UDP                 bool     `proxy:"udp,omitempty"`
	AcceptDNS           *bool    `proxy:"accept-dns,omitempty"`
	EnableExitNode      *bool    `proxy:"enable-exit-node,omitempty"`
	EnableEncryption    *bool    `proxy:"enable-encryption,omitempty"`
	EncryptionAlgorithm string   `proxy:"encryption-algorithm,omitempty"`
	PrivateMode         *bool    `proxy:"private-mode,omitempty"`
	LatencyFirst        *bool    `proxy:"latency-first,omitempty"`
	DisableP2P          *bool    `proxy:"disable-p2p,omitempty"`
	EnableKCPProxy      *bool    `proxy:"enable-kcp-proxy,omitempty"`
	DisableKCPInput     *bool    `proxy:"disable-kcp-input,omitempty"`
	EnableQUICProxy     *bool    `proxy:"enable-quic-proxy,omitempty"`
	DisableQUICInput    *bool    `proxy:"disable-quic-input,omitempty"`
	MTU                 int      `proxy:"mtu,omitempty"`
	TLDDNSZone          string   `proxy:"tld-dns-zone,omitempty"`
	SecureMode          *bool    `proxy:"secure-mode,omitempty"`
	LocalPrivateKey     string   `proxy:"local-private-key,omitempty"`
	LocalPublicKey      string   `proxy:"local-public-key,omitempty"`
}

func NewEasyTier(option EasyTierOption) (*EasyTier, error) {
	log.Warnln("[EasyTier] node %q is not built into this core: it stands in the configuration as a reject placeholder, and every connection through it is refused", option.Name)
	return &EasyTier{Reject: NewRejectWithOption(RejectOption{BasicOption: option.BasicOption, Name: option.Name})}, nil
}

func (e *EasyTier) ClashDeclaredType() C.AdapterType { return C.EasyTier }

func (e *EasyTier) MarshalJSON() ([]byte, error) {
	inner, err := e.Reject.MarshalJSON()
	if err != nil {
		return nil, err
	}
	mapping := map[string]any{}
	if err := json.Unmarshal(inner, &mapping); err != nil {
		return nil, err
	}
	mapping["placeholderType"] = "easytier"
	return json.Marshal(mapping)
}
