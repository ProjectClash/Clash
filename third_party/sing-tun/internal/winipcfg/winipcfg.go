/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2022 WireGuard LLC. All Rights Reserved.
 */

package winipcfg

import (
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)





func GetAdaptersAddresses(family AddressFamily, flags GAAFlags) ([]*IPAdapterAddresses, error) {
	var b []byte
	size := uint32(15000)

	for {
		b = make([]byte, size)
		err := windows.GetAdaptersAddresses(uint32(family), uint32(flags), 0, (*windows.IpAdapterAddresses)(unsafe.Pointer(&b[0])), &size)
		if err == nil {
			break
		}
		if err != windows.ERROR_BUFFER_OVERFLOW || size <= uint32(len(b)) {
			return nil, err
		}
	}

	result := make([]*IPAdapterAddresses, 0, uintptr(size)/unsafe.Sizeof(IPAdapterAddresses{}))
	for wtiaa := (*IPAdapterAddresses)(unsafe.Pointer(&b[0])); wtiaa != nil; wtiaa = wtiaa.Next {
		result = append(result, wtiaa)
	}

	return result, nil
}

func GetIPInterfaceTable(family AddressFamily) ([]MibIPInterfaceRow, error) {
	var tab *mibIPInterfaceTable
	err := getIPInterfaceTable(family, &tab)
	if err != nil {
		return nil, err
	}
	t := append(make([]MibIPInterfaceRow, 0, tab.numEntries), tab.get()...)
	tab.free()
	return t, nil
}

func GetIfTable2Ex(level MibIfEntryLevel) ([]MibIfRow2, error) {
	var tab *mibIfTable2
	err := getIfTable2Ex(level, &tab)
	if err != nil {
		return nil, err
	}
	t := append(make([]MibIfRow2, 0, tab.numEntries), tab.get()...)
	tab.free()
	return t, nil
}



func GetUnicastIPAddressTable(family AddressFamily) ([]MibUnicastIPAddressRow, error) {
	var tab *mibUnicastIPAddressTable
	err := getUnicastIPAddressTable(family, &tab)
	if err != nil {
		return nil, err
	}
	t := append(make([]MibUnicastIPAddressRow, 0, tab.numEntries), tab.get()...)
	tab.free()
	return t, nil
}



func GetAnycastIPAddressTable(family AddressFamily) ([]MibAnycastIPAddressRow, error) {
	var tab *mibAnycastIPAddressTable
	err := getAnycastIPAddressTable(family, &tab)
	if err != nil {
		return nil, err
	}
	t := append(make([]MibAnycastIPAddressRow, 0, tab.numEntries), tab.get()...)
	tab.free()
	return t, nil
}



func GetIPForwardTable2(family AddressFamily) ([]MibIPforwardRow2, error) {
	var tab *mibIPforwardTable2
	err := getIPForwardTable2(family, &tab)
	if err != nil {
		return nil, err
	}
	t := append(make([]MibIPforwardRow2, 0, tab.numEntries), tab.get()...)
	tab.free()
	return t, nil
}








func SetInterfaceDnsSettings(guid windows.GUID, settings *DnsInterfaceSettings) error {
	words := (*[4]uintptr)(unsafe.Pointer(&guid))
	switch runtime.GOARCH {
	case "amd64":
		return setInterfaceDnsSettingsByPtr(&guid, settings)
	case "arm64":
		return setInterfaceDnsSettingsByQwords(words[0], words[1], settings)
	case "arm", "386":
		return setInterfaceDnsSettingsByDwords(words[0], words[1], words[2], words[3], settings)
	default:
		panic("unknown calling convention")
	}
}
