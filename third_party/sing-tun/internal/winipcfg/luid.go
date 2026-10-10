/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2022 WireGuard LLC. All Rights Reserved.
 */

package winipcfg

import (
	"errors"
	"net/netip"
	"strings"

	"golang.org/x/sys/windows"
)

type LUID uint64

func (luid LUID) IPInterface(family AddressFamily) (*MibIPInterfaceRow, error) {
	row := &MibIPInterfaceRow{}
	row.Init()
	row.InterfaceLUID = luid
	row.Family = family
	err := row.get()
	if err != nil {
		return nil, err
	}
	return row, nil
}

func (luid LUID) Interface() (*MibIfRow2, error) {
	row := &MibIfRow2{}
	row.InterfaceLUID = luid
	err := row.get()
	if err != nil {
		return nil, err
	}
	return row, nil
}

func (luid LUID) GUID() (*windows.GUID, error) {
	guid := &windows.GUID{}
	err := convertInterfaceLUIDToGUID(&luid, guid)
	if err != nil {
		return nil, err
	}
	return guid, nil
}

func LUIDFromGUID(guid *windows.GUID) (LUID, error) {
	var luid LUID
	err := convertInterfaceGUIDToLUID(guid, &luid)
	if err != nil {
		return 0, err
	}
	return luid, nil
}

func LUIDFromIndex(index uint32) (LUID, error) {
	var luid LUID
	err := convertInterfaceIndexToLUID(index, &luid)
	if err != nil {
		return 0, err
	}
	return luid, nil
}

func (luid LUID) IPAddress(addr netip.Addr) (*MibUnicastIPAddressRow, error) {
	row := &MibUnicastIPAddressRow{InterfaceLUID: luid}

	err := row.Address.SetAddr(addr)
	if err != nil {
		return nil, err
	}

	err = row.get()
	if err != nil {
		return nil, err
	}

	return row, nil
}

func (luid LUID) AddIPAddress(address netip.Prefix) error {
	row := &MibUnicastIPAddressRow{}
	row.Init()
	row.InterfaceLUID = luid
	row.DadState = DadStatePreferred
	row.ValidLifetime = 0xffffffff
	row.PreferredLifetime = 0xffffffff
	err := row.Address.SetAddr(address.Addr())
	if err != nil {
		return err
	}
	row.OnLinkPrefixLength = uint8(address.Bits())
	return row.Create()
}

func (luid LUID) AddIPAddresses(addresses []netip.Prefix) error {
	for i := range addresses {
		err := luid.AddIPAddress(addresses[i])
		if err != nil {
			return err
		}
	}
	return nil
}

func (luid LUID) SetIPAddresses(addresses []netip.Prefix) error {
	err := luid.FlushIPAddresses(windows.AF_UNSPEC)
	if err != nil {
		return err
	}
	return luid.AddIPAddresses(addresses)
}

func (luid LUID) SetIPAddressesForFamily(family AddressFamily, addresses []netip.Prefix) error {
	err := luid.FlushIPAddresses(family)
	if err != nil {
		return err
	}
	for i := range addresses {
		if !addresses[i].Addr().Is4() && family == windows.AF_INET {
			continue
		} else if !addresses[i].Addr().Is6() && family == windows.AF_INET6 {
			continue
		}
		err := luid.AddIPAddress(addresses[i])
		if err != nil {
			return err
		}
	}
	return nil
}

func (luid LUID) DeleteIPAddress(address netip.Prefix) error {
	row := &MibUnicastIPAddressRow{}
	row.Init()
	row.InterfaceLUID = luid
	err := row.Address.SetAddr(address.Addr())
	if err != nil {
		return err
	}
	row.OnLinkPrefixLength = uint8(address.Bits())
	return row.Delete()
}

func (luid LUID) FlushIPAddresses(family AddressFamily) error {
	var tab *mibUnicastIPAddressTable
	err := getUnicastIPAddressTable(family, &tab)
	if err != nil {
		return err
	}
	t := tab.get()
	for i := range t {
		if t[i].InterfaceLUID == luid {
			t[i].Delete()
		}
	}
	tab.free()
	return nil
}

func (luid LUID) Route(destination netip.Prefix, nextHop netip.Addr) (*MibIPforwardRow2, error) {
	row := &MibIPforwardRow2{}
	row.Init()
	row.InterfaceLUID = luid
	row.ValidLifetime = 0xffffffff
	row.PreferredLifetime = 0xffffffff
	err := row.DestinationPrefix.SetPrefix(destination)
	if err != nil {
		return nil, err
	}
	err = row.NextHop.SetAddr(nextHop)
	if err != nil {
		return nil, err
	}

	err = row.get()
	if err != nil {
		return nil, err
	}
	return row, nil
}

func (luid LUID) AddRoute(destination netip.Prefix, nextHop netip.Addr, metric uint32) error {
	row := &MibIPforwardRow2{}
	row.Init()
	row.InterfaceLUID = luid
	err := row.DestinationPrefix.SetPrefix(destination)
	if err != nil {
		return err
	}
	err = row.NextHop.SetAddr(nextHop)
	if err != nil {
		return err
	}
	row.Metric = metric
	return row.Create()
}

func (luid LUID) AddRoutes(routesData []*RouteData) error {
	for _, rd := range routesData {
		err := luid.AddRoute(rd.Destination, rd.NextHop, rd.Metric)
		if err != nil {
			return err
		}
	}
	return nil
}

func (luid LUID) SetRoutes(routesData []*RouteData) error {
	err := luid.FlushRoutes(windows.AF_UNSPEC)
	if err != nil {
		return err
	}
	return luid.AddRoutes(routesData)
}

func (luid LUID) SetRoutesForFamily(family AddressFamily, routesData []*RouteData) error {
	err := luid.FlushRoutes(family)
	if err != nil {
		return err
	}
	for _, rd := range routesData {
		if !rd.Destination.Addr().Is4() && family == windows.AF_INET {
			continue
		} else if !rd.Destination.Addr().Is6() && family == windows.AF_INET6 {
			continue
		}
		err := luid.AddRoute(rd.Destination, rd.NextHop, rd.Metric)
		if err != nil {
			return err
		}
	}
	return nil
}

func (luid LUID) DeleteRoute(destination netip.Prefix, nextHop netip.Addr) error {
	row := &MibIPforwardRow2{}
	row.Init()
	row.InterfaceLUID = luid
	err := row.DestinationPrefix.SetPrefix(destination)
	if err != nil {
		return err
	}
	err = row.NextHop.SetAddr(nextHop)
	if err != nil {
		return err
	}
	err = row.get()
	if err != nil {
		return err
	}
	return row.Delete()
}

func (luid LUID) FlushRoutes(family AddressFamily) error {
	var tab *mibIPforwardTable2
	err := getIPForwardTable2(family, &tab)
	if err != nil {
		return err
	}
	t := tab.get()
	for i := range t {
		if t[i].InterfaceLUID == luid {
			err2 := t[i].Delete()
			if err2 != nil {
				err = err2
			}
		}
	}
	tab.free()
	return err
}

func (luid LUID) DNS() ([]netip.Addr, error) {
	addresses, err := GetAdaptersAddresses(windows.AF_UNSPEC, GAAFlagDefault)
	if err != nil {
		return nil, err
	}
	r := make([]netip.Addr, 0, len(addresses))
	for _, addr := range addresses {
		if addr.LUID == luid {
			for dns := addr.FirstDNSServerAddress; dns != nil; dns = dns.Next {
				if ip := dns.Address.IP(); ip != nil {
					if a, ok := netip.AddrFromSlice(ip); ok {
						r = append(r, a)
					}
				} else {
					return nil, windows.ERROR_INVALID_PARAMETER
				}
			}
		}
	}
	return r, nil
}

func (luid LUID) SetDNS(family AddressFamily, servers []netip.Addr, domains []string) error {
	if family != windows.AF_INET && family != windows.AF_INET6 {
		return windows.ERROR_PROTOCOL_UNREACHABLE
	}

	var filteredServers []string
	for _, server := range servers {
		if (server.Is4() && family == windows.AF_INET) || (server.Is6() && family == windows.AF_INET6) {
			filteredServers = append(filteredServers, server.String())
		}
	}
	servers16, err := windows.UTF16PtrFromString(strings.Join(filteredServers, ","))
	if err != nil {
		return err
	}
	domains16, err := windows.UTF16PtrFromString(strings.Join(domains, ","))
	if err != nil {
		return err
	}
	guid, err := luid.GUID()
	if err != nil {
		return err
	}
	dnsInterfaceSettings := &DnsInterfaceSettings{
		Version:    DnsInterfaceSettingsVersion1,
		Flags:      DnsInterfaceSettingsFlagNameserver | DnsInterfaceSettingsFlagSearchList,
		NameServer: servers16,
		SearchList: domains16,
	}
	if family == windows.AF_INET6 {
		dnsInterfaceSettings.Flags |= DnsInterfaceSettingsFlagIPv6
	}
	err = SetInterfaceDnsSettings(*guid, dnsInterfaceSettings)
	if err == nil || !errors.Is(err, windows.ERROR_PROC_NOT_FOUND) {
		return err
	}

	err = luid.fallbackSetDNSForFamily(family, servers)
	if err != nil {
		return err
	}
	if len(domains) > 0 {
		return luid.fallbackSetDNSDomain(domains[0])
	} else {
		return luid.fallbackSetDNSDomain("")
	}
}

func (luid LUID) FlushDNS(family AddressFamily) error {
	return luid.SetDNS(family, nil, nil)
}

func (luid LUID) DisableDNSRegistration() error {
	guid, err := luid.GUID()
	if err != nil {
		return err
	}

	dnsInterfaceSettings := &DnsInterfaceSettings{
		Version:             DnsInterfaceSettingsVersion1,
		Flags:               DnsInterfaceSettingsFlagRegistrationEnabled,
		RegistrationEnabled: 0,
	}

	err = SetInterfaceDnsSettings(*guid, dnsInterfaceSettings)
	if err == nil || !errors.Is(err, windows.ERROR_PROC_NOT_FOUND) {
		return err
	}

	return luid.fallbackDisableDNSRegistration()
}
