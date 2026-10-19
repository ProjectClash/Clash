package inbound

import (
	"strings"

	C "github.com/ProjectClash/Clash/constant"
	LC "github.com/ProjectClash/Clash/listener/config"
	"github.com/ProjectClash/Clash/listener/mtproto"
	"github.com/ProjectClash/Clash/log"
)

type MTProtoOption struct {
	BaseOption
	Secret string `inbound:"secret"`
	IPv6   bool   `inbound:"ipv6,omitempty"`
	DCConfigURL string `inbound:"dc-config-url,omitempty"`
}

func (o MTProtoOption) Equal(config C.InboundConfig) bool {
	return optionToString(o) == optionToString(config)
}

type MTProto struct {
	*Base
	config  *MTProtoOption
	l       C.MultiAddrListener
	mtproto LC.MTProtoServer
}

func NewMTProto(options *MTProtoOption) (*MTProto, error) {
	base, err := NewBase(&options.BaseOption)
	if err != nil {
		return nil, err
	}
	if _, err := mtproto.ParseSecret(options.Secret); err != nil {
		return nil, err
	}
	return &MTProto{
		Base:   base,
		config: options,
		mtproto: LC.MTProtoServer{
			Listen: base.RawAddress(),
			Secret: options.Secret,
			IPv6:   options.IPv6,
		},
	}, nil
}

func (m *MTProto) Config() C.InboundConfig {
	return m.config
}

func (m *MTProto) Address() string {
	var addrList []string
	if m.l != nil {
		for _, addr := range m.l.AddrList() {
			addrList = append(addrList, addr.String())
		}
	}
	return strings.Join(addrList, ",")
}

func (m *MTProto) Listen(tunnel C.Tunnel) error {
	var err error
	m.l, err = mtproto.New(m.mtproto, m.ListenConfig(), tunnel, m.Additions()...)
	if err != nil {
		return err
	}
	log.Infoln("MTProto[%s] proxy listening at: %s", m.Name(), m.Address())
	return nil
}

func (m *MTProto) Close() error {
	if m.l == nil {
		return nil
	}
	return m.l.Close()
}

var _ C.InboundListener = (*MTProto)(nil)
