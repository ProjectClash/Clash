//go:build with_low_memory

package net

import (
	"errors"
	"io"
	"sync/atomic"

	"github.com/metacubex/sing/common/bufio"
	N "github.com/metacubex/sing/common/network"
)

const (
	relayBurstMTU    = 16 * 1024
	relayBurstBudget = 2 * 1024 * 1024
)

var relayBurstsHeld atomic.Int64

func acquireRelayBurst() bool {
	for {
		held := relayBurstsHeld.Load()
		if held >= relayBurstBudget/relayBurstMTU {
			return false
		}
		if relayBurstsHeld.CompareAndSwap(held, held+1) {
			return true
		}
	}
}

func releaseRelayBurst() { relayBurstsHeld.Add(-1) }

func streamRelayCopy(destination *boundedRelayWriter, source N.ExtendedReader, originSource io.Reader, readCounters, writeCounters []N.CountFunc) (int64, error) {
	small := N.NewReadWaitOptions(source, destination)
	burst := small
	if burstMTU := relayBurstMTU - burst.FrontHeadroom - burst.RearHeadroom; burst.MTU > 0 && burst.MTU < burstMTU {
		burst.MTU = burstMTU
	}
	if readWaiter, waits := bufio.CreateReadWaiter(source); waits {
		readWaiter.InitializeReadWaiter(burst)
		return waitRelayCopy(destination, readWaiter, originSource, readCounters, writeCounters)
	}
	if small.MTU <= 0 || small.MTU >= burst.MTU {
		return bufio.CopyExtendedWithPool(originSource, destination, source, readCounters, writeCounters)
	}
	return burstRelayCopy(destination, source, originSource, readCounters, writeCounters, small, burst)
}

func waitRelayCopy(destination N.ExtendedWriter, source N.ReadWaiter, originSource io.Reader, readCounters, writeCounters []N.CountFunc) (n int64, err error) {
	var notFirstTime bool
	for {
		buffer, waitErr := source.WaitReadBuffer()
		if waitErr != nil {
			if !errors.Is(waitErr, io.EOF) {
				err = waitErr
			}
			return
		}
		dataLen := buffer.Len()
		err = destination.WriteBuffer(buffer)
		if err != nil {
			buffer.Leak()
			if !notFirstTime {
				err = N.ReportHandshakeFailure(originSource, err)
			}
			return
		}
		n += int64(dataLen)
		countRelayBytes(readCounters, int64(dataLen))
		countRelayBytes(writeCounters, int64(dataLen))
		notFirstTime = true
	}
}

func burstRelayCopy(destination N.ExtendedWriter, source N.ExtendedReader, originSource io.Reader, readCounters, writeCounters []N.CountFunc, small, burst N.ReadWaitOptions) (n int64, err error) {
	options := small
	bursting := false
	defer func() {
		if bursting {
			releaseRelayBurst()
		}
	}()
	var notFirstTime bool
	for {
		buffer := options.NewBuffer()
		err = source.ReadBuffer(buffer)
		if err != nil {
			buffer.Release()
			if errors.Is(err, io.EOF) {
				err = nil
			}
			return
		}
		dataLen := buffer.Len()
		options.PostReturn(buffer)
		err = destination.WriteBuffer(buffer)
		if err != nil {
			buffer.Leak()
			if !notFirstTime {
				err = N.ReportHandshakeFailure(originSource, err)
			}
			return
		}
		n += int64(dataLen)
		countRelayBytes(readCounters, int64(dataLen))
		countRelayBytes(writeCounters, int64(dataLen))
		notFirstTime = true
		switch {
		case !bursting && dataLen >= small.MTU && acquireRelayBurst():
			bursting, options = true, burst
		case bursting && dataLen < burst.MTU:
			releaseRelayBurst()
			bursting, options = false, small
		}
	}
}
