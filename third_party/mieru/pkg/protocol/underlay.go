// Copyright (C) 2023  mieru authors
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
// along with this program.  If not, see <https://www.gnu.org/licenses/>

package protocol

import (
	"context"
	"net"

	"github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"github.com/enfein/mieru/v3/pkg/common"
	"github.com/enfein/mieru/v3/pkg/metrics"
)

var (
	UnderlayMaxConn         = metrics.RegisterMetric("underlay", "MaxConn", metrics.GAUGE)
	UnderlayActiveOpens     = metrics.RegisterMetric("underlay", "ActiveOpens", metrics.COUNTER)
	UnderlayPassiveOpens    = metrics.RegisterMetric("underlay", "PassiveOpens", metrics.COUNTER)
	UnderlayCurrEstablished = metrics.RegisterMetric("underlay", "CurrEstablished", metrics.GAUGE)
	UnderlayMalformedUDP    = metrics.RegisterMetric("underlay", "UnderlayMalformedUDP", metrics.COUNTER)
	UnderlayUnsolicitedUDP  = metrics.RegisterMetric("underlay", "UnsolicitedUDP", metrics.COUNTER)
)

type UnderlayProperties interface {
	MTU() int

	TransportProtocol() common.TransportProtocol

	LocalAddr() net.Addr

	RemoteAddr() net.Addr
}

type Underlay interface {
	net.Listener

	UnderlayProperties

	AddSession(*Session, net.Addr) error

	RemoveSession(*Session) error

	SessionCount() int

	SessionInfos() []*appctlpb.SessionInfo

	InBytes() int64

	OutBytes() int64

	RunEventLoop(context.Context) error

	Scheduler() *ScheduleController

	Done() chan struct{}
}

type underlayDescriptor struct {
	mtu               int
	transportProtocol common.TransportProtocol
	localAddr         net.Addr
	remoteAddr        net.Addr
}

var _ UnderlayProperties = &underlayDescriptor{}

func (d *underlayDescriptor) MTU() int {
	return d.mtu
}

func (d *underlayDescriptor) TransportProtocol() common.TransportProtocol {
	return d.transportProtocol
}

func (d *underlayDescriptor) LocalAddr() net.Addr {
	return d.localAddr
}

func (d *underlayDescriptor) RemoteAddr() net.Addr {
	return d.remoteAddr
}

func NewUnderlayProperties(mtu int, transportProtocol common.TransportProtocol, localAddr net.Addr, remoteAddr net.Addr) UnderlayProperties {
	d := &underlayDescriptor{
		mtu:               mtu,
		transportProtocol: transportProtocol,
		localAddr:         localAddr,
		remoteAddr:        remoteAddr,
	}
	if localAddr == nil {
		d.localAddr = common.NilNetAddr()
	}
	if remoteAddr == nil {
		d.remoteAddr = common.NilNetAddr()
	}
	return d
}
