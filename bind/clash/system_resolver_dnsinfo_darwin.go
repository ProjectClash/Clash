//go:build darwin && cgo

package clash

/*
#include <dlfcn.h>
#include <notify.h>
#include <stdint.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>

// The resolvers a packet tunnel cannot otherwise see.
//
// res_ninit (system_resolver_libresolv_darwin.go) reads configd's DNS configuration, and
// inside an Apple packet tunnel that configuration is the tunnel's own NEDNSSettings: once
// they apply, the extension asks res_ninit and is told its own address, or nothing at all
// (measured on an iPhone, 2026-09-17: after the settings apply every read answers none, on
// every path callback and on a timer). The physical network's resolvers are still there --
// libsystem_configuration keeps them as PER-INTERFACE SCOPED resolvers, which res_ninit does
// not expose. dns_configuration_copy does.
//
// dnsinfo.h ships in no SDK. The layouts below are DNSINFO_VERSION 20170629 from
// apple-oss-distributions/configd (#pragma pack(4)), which is the shape
// libsystem_configuration unpacks into at runtime. dns_configuration_copy,
// dns_configuration_free and dns_configuration_notify_key are private libSystem exports
// resolved through dlsym; the symbol names are written backwards and reversed at runtime, the
// way the reference implementation does it (sing-box dns/transport/local/systemconfig).
// cgo silently drops packed struct fields on unaligned offsets, so every field is named here
// rather than reached through the SDK's own header.
//
// This is a private API. The ruling to use it is the user's, 2026-09-18, after the App Store
// review risk was put to them:.

#pragma pack(4)
typedef struct {
	struct in_addr address;
	struct in_addr mask;
} clash_dns_sortaddr_t;

typedef struct {
	char *domain;
	int32_t n_nameserver;
	struct sockaddr **nameserver;
	uint16_t port;
	int32_t n_search;
	char **search;
	int32_t n_sortaddr;
	clash_dns_sortaddr_t **sortaddr;
	char *options;
	uint32_t timeout;
	uint32_t search_order;
	uint32_t if_index;
	uint32_t flags;
	uint32_t reach_flags;
	uint32_t service_identifier;
	char *cid;
	char *if_name;
} clash_dns_resolver_t;

typedef struct {
	int32_t n_resolver;
	clash_dns_resolver_t **resolver;
	int32_t n_scoped_resolver;
	clash_dns_resolver_t **scoped_resolver;
	uint64_t generation;
	int32_t n_service_specific_resolver;
	clash_dns_resolver_t **service_specific_resolver;
	uint32_t version;
} clash_dns_config_t;
#pragma pack()

static clash_dns_config_t *(*clash_dns_configuration_copy)(void);
static void (*clash_dns_configuration_free)(clash_dns_config_t *);

static void clash_reverse_string(char *s) {
	size_t length = strlen(s);
	for (size_t i = 0; i < length / 2; i++) {
		char tmp = s[i];
		s[i] = s[length - 1 - i];
		s[length - 1 - i] = tmp;
	}
}

static int clash_dnsinfo_load(void) {
	if (clash_dns_configuration_copy != NULL && clash_dns_configuration_free != NULL) {
		return 1;
	}
	char copy_name[] = "ypoc_noitarugifnoc_snd";
	char free_name[] = "eerf_noitarugifnoc_snd";
	clash_reverse_string(copy_name);
	clash_reverse_string(free_name);
	clash_dns_configuration_copy = (clash_dns_config_t * (*)(void)) dlsym(RTLD_DEFAULT, copy_name);
	clash_dns_configuration_free = (void (*)(clash_dns_config_t *))dlsym(RTLD_DEFAULT, free_name);
	return clash_dns_configuration_copy != NULL && clash_dns_configuration_free != NULL;
}

static clash_dns_config_t *clash_dnsinfo_copy(void) { return clash_dns_configuration_copy(); }

static void clash_dnsinfo_free(clash_dns_config_t *config) { clash_dns_configuration_free(config); }

static const char *clash_dnsinfo_notify_key(void) {
	const char *(*notify_key)(void) = (const char *(*)(void))dlsym(RTLD_DEFAULT, "dns_configuration_notify_key");
	if (notify_key != NULL) {
		return notify_key();
	}
	return "com.apple.system.SystemConfiguration.dns_configuration";
}

static clash_dns_resolver_t *clash_dnsinfo_default_resolver(clash_dns_config_t *config, int32_t index) {
	return config->resolver[index];
}

static clash_dns_resolver_t *clash_dnsinfo_scoped_resolver(clash_dns_config_t *config, int32_t index) {
	return config->scoped_resolver[index];
}

static struct sockaddr *clash_dnsinfo_nameserver(clash_dns_resolver_t *resolver, int32_t index) {
	return resolver->nameserver[index];
}
*/
import "C"

import (
	"encoding/binary"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"unsafe"
)

var (
	dnsInfoLoadOnce sync.Once
	dnsInfoLoaded   bool

	dnsInfoNotifyMu    sync.Mutex
	dnsInfoNotifyToken C.int
	dnsInfoNotifyValid bool
)

func dnsInfoAvailable() bool {
	dnsInfoLoadOnce.Do(func() {
		dnsInfoLoaded = C.clash_dnsinfo_load() != 0
		if !dnsInfoLoaded {
			return
		}
		var token C.int
		if C.notify_register_check(C.clash_dnsinfo_notify_key(), &token) == 0 {
			dnsInfoNotifyMu.Lock()
			dnsInfoNotifyToken = token
			dnsInfoNotifyValid = true
			dnsInfoNotifyMu.Unlock()
		}
	})
	return dnsInfoLoaded
}

func dnsInfoChanged() bool {
	if !dnsInfoAvailable() {
		return false
	}
	dnsInfoNotifyMu.Lock()
	defer dnsInfoNotifyMu.Unlock()
	if !dnsInfoNotifyValid {
		return true
	}
	var changed C.int
	if C.notify_check(dnsInfoNotifyToken, &changed) != 0 {
		return true
	}
	return changed != 0
}

func physicalResolversForInterface(index int32) []string {
	if !dnsInfoAvailable() {
		return nil
	}
	rawConfig := C.clash_dnsinfo_copy()
	if rawConfig == nil {
		return nil
	}
	defer C.clash_dnsinfo_free(rawConfig)
	if index > 0 {
		for i := C.int32_t(0); i < rawConfig.n_scoped_resolver; i++ {
			resolver := C.clash_dnsinfo_scoped_resolver(rawConfig, i)
			if resolver == nil || int32(resolver.if_index) != index {
				continue
			}
			if servers := dnsInfoResolverServers(resolver); len(servers) != 0 {
				return servers
			}
		}
	}
	if !unscopedResolversArePhysical.Load() {
		return nil
	}
	for i := C.int32_t(0); i < rawConfig.n_resolver; i++ {
		resolver := C.clash_dnsinfo_default_resolver(rawConfig, i)
		if resolver == nil || C.GoString(resolver.domain) != "" {
			continue
		}
		if servers := dnsInfoResolverServers(resolver); len(servers) != 0 {
			return servers
		}
	}
	return nil
}

func dnsInfoResolverServers(resolver *C.clash_dns_resolver_t) []string {
	port := uint16(resolver.port)
	if port == 0 {
		port = 53
	}
	zone := C.GoString(resolver.if_name)
	var servers []string
	for i := C.int32_t(0); i < resolver.n_nameserver; i++ {
		rawSockaddr := C.clash_dnsinfo_nameserver(resolver, i)
		if rawSockaddr == nil {
			continue
		}
		addrPort, ok := dnsInfoSockaddr(rawSockaddr, port, zone)
		if !ok {
			continue
		}
		addr := addrPort.Addr()
		if !addr.IsValid() || addr.IsUnspecified() || addr.IsLoopback() {
			continue
		}
		if addr.IsLinkLocalUnicast() && addr.Zone() == "" {
			continue
		}
		servers = append(servers, net.JoinHostPort(addr.Unmap().String(), strconv.Itoa(int(addrPort.Port()))))
	}
	return servers
}

func dnsInfoSockaddr(rawSockaddr *C.struct_sockaddr, fallbackPort uint16, zone string) (netip.AddrPort, bool) {
	switch rawSockaddr.sa_family {
	case C.AF_INET:
		sockaddrInet := (*C.struct_sockaddr_in)(unsafe.Pointer(rawSockaddr))
		addr := netip.AddrFrom4(*(*[4]byte)(unsafe.Pointer(&sockaddrInet.sin_addr)))
		return netip.AddrPortFrom(addr, dnsInfoPort(unsafe.Pointer(&sockaddrInet.sin_port), fallbackPort)), true
	case C.AF_INET6:
		sockaddrInet6 := (*C.struct_sockaddr_in6)(unsafe.Pointer(rawSockaddr))
		addr := netip.AddrFrom16(*(*[16]byte)(unsafe.Pointer(&sockaddrInet6.sin6_addr)))
		if addr.IsLinkLocalUnicast() {
			scopeID := uint32(sockaddrInet6.sin6_scope_id)
			if zone == "" && scopeID != 0 {
				zone = strconv.FormatUint(uint64(scopeID), 10)
			}
			if zone != "" {
				addr = addr.WithZone(zone)
			}
		}
		return netip.AddrPortFrom(addr, dnsInfoPort(unsafe.Pointer(&sockaddrInet6.sin6_port), fallbackPort)), true
	default:
		return netip.AddrPort{}, false
	}
}

func dnsInfoPort(rawPort unsafe.Pointer, fallbackPort uint16) uint16 {
	port := binary.BigEndian.Uint16((*[2]byte)(rawPort)[:])
	if port == 0 {
		return fallbackPort
	}
	return port
}
