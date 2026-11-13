// Copyright (C) 2025  mieru authors
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

package server

import (
	"errors"
	"net"

	apicommon "github.com/enfein/mieru/v3/apis/common"
	"github.com/enfein/mieru/v3/apis/model"
	"github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
)

var (
	ErrNoServerConfig              = errors.New("no server config")
	ErrInvalidServerConfig         = errors.New("invalid server config")
	ErrServerIsNotRunning          = errors.New("server is not running")
	ErrStoreServerConfigAfterStart = errors.New("can't store server config after start")
)

type Server interface {
	ServerConfigurationService
	ServerLifecycleService
	ServerNetworkService
}

type ServerConfigurationService interface {
	Load() (*ServerConfig, error)

	Store(*ServerConfig) error
}

type ServerLifecycleService interface {
	Start() error

	Stop() error

	IsRunning() bool
}

type ServerNetworkService interface {
	Accept() (net.Conn, *model.Request, error)
}

type ServerConfig struct {
	Config *appctlpb.ServerConfig

	StreamListenerFactory apicommon.StreamListenerFactory

	PacketListenerFactory apicommon.PacketListenerFactory
}

func NewServer() Server {
	ms := &mieruServer{}
	ms.initOnce()
	return ms
}
