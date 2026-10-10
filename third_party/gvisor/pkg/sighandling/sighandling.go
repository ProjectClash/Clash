// Copyright 2018 The gVisor Authors.
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

package sighandling

import (
	"os"
	"os/signal"
	"reflect"

	"golang.org/x/sys/unix"
	"github.com/metacubex/gvisor/pkg/abi/linux"
)

const numSignals = 32

func handleSignals(sigchans []chan os.Signal, handler func(linux.Signal), stop, done chan struct{}) {
	sc := []reflect.SelectCase{{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(stop)}}
	for _, sigchan := range sigchans {
		sc = append(sc, reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(sigchan)})
	}

	for {
		index, _, ok := reflect.Select(sc)

		if index == 0 {
			if !ok {
				close(done)
				return
			}
			continue
		}

		if !ok {
			panic("signal channel closed unexpectedly")
		}

		handler(linux.Signal(index))
	}
}

func StartSignalForwarding(handler func(linux.Signal)) func() {
	stop := make(chan struct{})
	done := make(chan struct{})

	var sigchans []chan os.Signal
	for sig := 1; sig <= numSignals+1; sig++ {
		sigchan := make(chan os.Signal, 1)
		sigchans = append(sigchans, sigchan)

		if sig == int(linux.SIGURG) {
			continue
		}
		if sig == int(linux.SIGPIPE) {
			continue
		}
		if sig == int(linux.SIGCHLD) {
			continue
		}
		signal.Notify(sigchan, unix.Signal(sig))
	}
	go handleSignals(sigchans, handler, stop, done)

	return func() {
		close(stop)
		<-done
	}
}
