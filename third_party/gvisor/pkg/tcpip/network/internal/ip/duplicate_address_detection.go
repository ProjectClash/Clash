// Copyright 2021 The gVisor Authors.
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

package ip

import (
	"bytes"
	"fmt"
	"io"

	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
)

type extendRequest int

const (
	notRequested extendRequest = iota
	requested
	extended
)

type dadState struct {
	nonce         []byte
	extendRequest extendRequest

	done  *bool
	timer tcpip.Timer `state:"nosave"`

	completionHandlers []stack.DADCompletionHandler
}

type DADProtocol interface {
	SendDADMessage(tcpip.Address, []byte) tcpip.Error
}

type DADOptions struct {
	Clock tcpip.Clock
	SecureRNG          io.Reader `state:"nosave"`
	NonceSize          uint8
	ExtendDADTransmits uint8
	Protocol           DADProtocol
	NICID              tcpip.NICID
}

type DAD struct {
	opts    DADOptions
	configs stack.DADConfigurations

	protocolMU sync.Locker `state:"nosave"`
	addresses  map[tcpip.Address]dadState
}

func (d *DAD) Init(protocolMU sync.Locker, configs stack.DADConfigurations, opts DADOptions) {
	if d.addresses != nil {
		panic("attempted to initialize DAD state twice")
	}

	if opts.NonceSize != 0 && opts.ExtendDADTransmits == 0 {
		panic(fmt.Sprintf("given a non-zero value for NonceSize (%d) but zero for ExtendDADTransmits", opts.NonceSize))
	}

	configs.Validate()

	*d = DAD{
		opts:       opts,
		configs:    configs,
		protocolMU: protocolMU,
		addresses:  make(map[tcpip.Address]dadState),
	}
}

func (d *DAD) CheckDuplicateAddressLocked(addr tcpip.Address, h stack.DADCompletionHandler) stack.DADCheckAddressDisposition {
	if d.configs.DupAddrDetectTransmits == 0 {
		return stack.DADDisabled
	}

	ret := stack.DADAlreadyRunning
	s, ok := d.addresses[addr]
	if !ok {
		ret = stack.DADStarting

		remaining := d.configs.DupAddrDetectTransmits

		done := false

		s = dadState{
			done: &done,
			timer: d.opts.Clock.AfterFunc(0, func() {
				dadDone := remaining == 0

				nonce, earlyReturn := func() ([]byte, bool) {
					d.protocolMU.Lock()
					defer d.protocolMU.Unlock()

					if done {
						return nil, true
					}

					s, ok := d.addresses[addr]
					if !ok {
						panic(fmt.Sprintf("dad: timer fired but missing state for %s on NIC(%d)", addr, d.opts.NICID))
					}

					if dadDone && s.extendRequest == requested {
						dadDone = false
						remaining = d.opts.ExtendDADTransmits
						s.extendRequest = extended
					}

					if !dadDone && d.opts.NonceSize != 0 {
						if s.nonce == nil {
							s.nonce = make([]byte, d.opts.NonceSize)
						}

						if n, err := io.ReadFull(d.opts.SecureRNG, s.nonce); err != nil {
							panic(fmt.Sprintf("SecureRNG.Read(...): %s", err))
						} else if n != len(s.nonce) {
							panic(fmt.Sprintf("expected to read %d bytes from secure RNG, only read %d bytes", len(s.nonce), n))
						}
					}

					d.addresses[addr] = s
					return s.nonce, false
				}()
				if earlyReturn {
					return
				}

				var err tcpip.Error
				if !dadDone {
					err = d.opts.Protocol.SendDADMessage(addr, nonce)
				}

				d.protocolMU.Lock()
				defer d.protocolMU.Unlock()

				if done {
					return
				}

				s, ok := d.addresses[addr]
				if !ok {
					panic(fmt.Sprintf("dad: timer fired but missing state for %s on NIC(%d)", addr, d.opts.NICID))
				}

				if !dadDone && err == nil {
					remaining--
					s.timer.Reset(d.configs.RetransmitTimer)
					return
				}

				done = false
				s.timer.Stop()
				delete(d.addresses, addr)

				var res stack.DADResult = &stack.DADSucceeded{}
				if err != nil {
					res = &stack.DADError{Err: err}
				}
				for _, h := range s.completionHandlers {
					h(res)
				}
			}),
		}
	}

	s.completionHandlers = append(s.completionHandlers, h)
	d.addresses[addr] = s
	return ret
}

type ExtendIfNonceEqualLockedDisposition int

const (
	Extended ExtendIfNonceEqualLockedDisposition = iota

	AlreadyExtended

	NoDADStateFound

	NonceDisabled

	NonceNotEqual
)

func (d *DAD) ExtendIfNonceEqualLocked(addr tcpip.Address, nonce []byte) ExtendIfNonceEqualLockedDisposition {
	s, ok := d.addresses[addr]
	if !ok {
		return NoDADStateFound
	}

	if d.opts.NonceSize == 0 {
		return NonceDisabled
	}

	if s.extendRequest != notRequested {
		return AlreadyExtended
	}

	if s.nonce != nil && bytes.Equal(s.nonce, nonce) {
		s.extendRequest = requested
		d.addresses[addr] = s
		return Extended
	}

	return NonceNotEqual
}

func (d *DAD) StopLocked(addr tcpip.Address, reason stack.DADResult) {
	s, ok := d.addresses[addr]
	if !ok {
		return
	}

	*s.done = true
	s.timer.Stop()
	delete(d.addresses, addr)

	for _, h := range s.completionHandlers {
		h(reason)
	}
}

func (d *DAD) SetConfigsLocked(c stack.DADConfigurations) {
	c.Validate()
	d.configs = c
}
