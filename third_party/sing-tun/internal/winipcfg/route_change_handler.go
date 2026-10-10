/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2022 WireGuard LLC. All Rights Reserved.
 */

package winipcfg

import (
	"sync"

	"golang.org/x/sys/windows"
)

type RouteChangeCallback struct {
	cb   func(notificationType MibNotificationType, route *MibIPforwardRow2)
	wait sync.WaitGroup
}

var (
	routeChangeAddRemoveMutex = sync.Mutex{}
	routeChangeMutex          = sync.Mutex{}
	routeChangeCallbacks      = make(map[*RouteChangeCallback]bool)
	routeChangeHandle         = windows.Handle(0)
)

func RegisterRouteChangeCallback(callback func(notificationType MibNotificationType, route *MibIPforwardRow2)) (*RouteChangeCallback, error) {
	s := &RouteChangeCallback{cb: callback}

	routeChangeAddRemoveMutex.Lock()
	defer routeChangeAddRemoveMutex.Unlock()

	routeChangeMutex.Lock()
	defer routeChangeMutex.Unlock()

	routeChangeCallbacks[s] = true

	if routeChangeHandle == 0 {
		err := notifyRouteChange2(windows.AF_UNSPEC, windows.NewCallback(routeChanged), 0, false, &routeChangeHandle)
		if err != nil {
			delete(routeChangeCallbacks, s)
			routeChangeHandle = 0
			return nil, err
		}
	}

	return s, nil
}

func (callback *RouteChangeCallback) Unregister() error {
	routeChangeAddRemoveMutex.Lock()
	defer routeChangeAddRemoveMutex.Unlock()

	routeChangeMutex.Lock()
	delete(routeChangeCallbacks, callback)
	removeIt := len(routeChangeCallbacks) == 0 && routeChangeHandle != 0
	routeChangeMutex.Unlock()

	callback.wait.Wait()

	if removeIt {
		err := cancelMibChangeNotify2(routeChangeHandle)
		if err != nil {
			return err
		}
		routeChangeHandle = 0
	}

	return nil
}

func routeChanged(callerContext uintptr, row *MibIPforwardRow2, notificationType MibNotificationType) uintptr {
	rowCopy := *row
	routeChangeMutex.Lock()
	for cb := range routeChangeCallbacks {
		cb.wait.Add(1)
		go func(cb *RouteChangeCallback) {
			cb.cb(notificationType, &rowCopy)
			cb.wait.Done()
		}(cb)
	}
	routeChangeMutex.Unlock()
	return 0
}
