// Copyright (C) 2024  mieru authors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package client

import (
	"context"
	"errors"
	"net"

	apicommon "github.com/enfein/mieru/v3/apis/common"
	"github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
)

var (
	ErrNoClientConfig              = errors.New("no client config")
	ErrInvalidClientConfig         = errors.New("invalid client config")
	ErrClientIsNotRunning          = errors.New("client is not running")
	ErrStoreClientConfigAfterStart = errors.New("can't store client config after start")
)

type Client interface {
	ClientConfigurationService
	ClientLifecycleService
	ClientNetworkService
}

type ClientConfigurationService interface {
	Load() (*ClientConfig, error)

	Store(*ClientConfig) error
}

type ClientLifecycleService interface {
	Start() error

	Stop() error

	IsRunning() bool
}

type ClientNetworkService interface {
	DialContext(context.Context, net.Addr) (net.Conn, error)
}

type ClientConfig struct {
	Profile *appctlpb.ClientProfile

	Dialer apicommon.Dialer

	PacketDialer apicommon.PacketDialer

	Resolver apicommon.DNSResolver

	DNSConfig *apicommon.ClientDNSConfig
}

func NewClient() Client {
	mc := &mieruClient{}
	mc.initOnce()
	return mc
}
