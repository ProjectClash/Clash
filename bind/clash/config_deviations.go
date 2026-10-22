package clash

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync/atomic"

	"github.com/ProjectClash/Clash/log"
	"go.yaml.in/yaml/v3"
)

const (
	deviationStripped    = "stripped"
	deviationForced      = "forced"
	deviationUnavailable = "unavailable"
)

const configDeviationSchemaVersion = 1

type configDeviation struct {
	Field           string `json:"field"`
	Given           string `json:"given"`
	Effective       string `json:"effective"`
	Category        string `json:"category"`
	Reason          string `json:"reason"`
	Source          string `json:"source"`
	Recoverable     bool   `json:"recoverable"`
	Alternative     string `json:"alternative,omitempty"`
	Effect          string `json:"effect,omitempty"`
	Mechanism       string `json:"mechanism,omitempty"`
	Written         bool   `json:"written"`
	UpstreamDefault string `json:"upstreamDefault,omitempty"`
	RuleKind        string `json:"ruleKind,omitempty"`
	Honoured        bool   `json:"honoured,omitempty"`
}

type deviationRule struct {
	field                  string
	category               string
	effective              string
	reason                 string
	source                 string
	recoverable            bool
	alternative            string
	withheld               bool
	ruleScan               bool
	ruleKind               string
	applies                func(policy appleRuntimePolicy) bool
	condition              string
	upstreamDefault        string
	honouredBy             string
	defaultOnly            bool
	forcedValue            string
	forcedFrom             []string
	unwrittenUnconditional bool
	// mechanism is the developer's half of the reason: the file, function, API type, kernel
	// constant or tool that makes the sentence true. It exists so that reason can be written
	// for the person changing a setting -- what happened to them, what they can do -- while the
	// material that proves it lives here. Clients keep mechanism and source for the diagnostics
	// export and never put them on screen. The user's words on seeing
	// "bind/clash/config_pipeline.go:119-124 (the StoreFakeIPSet guard)" under a setting: that is
	// Go's decision-making shown to someone who came to change a setting.
	mechanism string
}

const (
	tunPacketTunnelShape = "on Apple the tunnel is the only shape this extension can take, so there is no setting that turns it off"
	tunRoutingIsApples   = "on Apple the routes are installed by the app, not by the core, so the core-side routing switches have nothing to act on"
	tunOffloadBridge     = "on Apple the tunnel has no network driver to negotiate offload with, so offload cannot be turned on"
	tunBatchIOBridge     = "on Apple the tunnel does not expose the batched read/write path these fields select, so the ordinary path is used instead; nothing is lost but the batching"
	tunAutoRouteFilter   = "this filters traffic with Linux routing rules; the core accepts it on Apple and does nothing with it, exactly as it does on any non-Linux platform"

	tunPacketTunnelShapeMechanism = "a packet tunnel provider is a tun by construction: there is no no-tun shape for the extension to take"
	tunRoutingIsApplesMechanism   = "routes belong to NEPacketTunnelNetworkSettings and are installed by the extension's Swift side; the core does not own a host routing table here"
	tunOffloadBridgeMechanism     = "the data plane is NEPacketTunnelFlow bridged through a SOCK_DGRAM descriptor rather than a utun fd; segmentation offload is negotiated with a tun driver, and the bridge descriptor has no such driver to negotiate with"
	tunBatchIOBridgeMechanism     = "the data plane is NEPacketTunnelFlow bridged through a SOCK_DGRAM descriptor rather than a utun fd, so the batched utun-fd read/write path these fields select uses ordinary readv/writev instead (this is about the fd, not about socket options -- IP_BOUND_IF is a socket option and works fine over the bridge)"
	tunAutoRouteFilterMechanism   = "read only by sing-tun's Linux ip-rule and nftables/iptables code (tun_linux.go, redirect_*.go); upstream's listener hands it to sing-tun on every platform and the Darwin tun never reads it, so it reaches the core as written"

	tunIncludeAllNetworks = "a file that names no stack keeps gvisor, the stack this tunnel has been measured on -- " +
		"upstream now defaults to mips, which has not yet been measured here; and with Include All " +
		"Networks on, the system and mixed stacks send nothing, so only gvisor carries the tunnel's traffic"
	tunIncludeAllNetworksMechanism = "an unwritten tun.stack is set to gvisor before the parse (bind/clash/config_pipeline.go " +
		"applyAppleDefaults; upstream config/config.go DefaultRawConfig has TunMips since v1.19.32). " +
		"Include All Networks makes the kernel drop, at ip_output, every packet that does not leave " +
		"through the tunnel; the system and mixed stacks re-inject the tunnel's TCP through the kernel " +
		"and lose it there, which is why sing-tun refuses both under includeAllNetworks (third_party/sing-tun/stack.go)"
)

func underNetworkExtension(policy appleRuntimePolicy) bool { return policy.networkExtension }

const (
	deviationConditionIncludeAllNetworks = "includeAllNetworks"
	deviationConditionLANSharingOff      = "lanSharingOff"
)

func deviationConditionHolds(condition string) bool {
	switch condition {
	case "":
		return true
	case deviationConditionIncludeAllNetworks:
		return includeAllNetworksActive()
	case deviationConditionLANSharingOff:
		return allowLanForcedOff.Load()
	}
	return false
}

func (r *deviationRule) active(policy appleRuntimePolicy) bool {
	return (r.applies == nil || r.applies(policy)) && deviationConditionHolds(r.condition)
}

func (r *deviationRule) activeFor(policy appleRuntimePolicy, written bool) bool {
	if r.unwrittenUnconditional && !written {
		return r.applies == nil || r.applies(policy)
	}
	return r.active(policy)
}

func underPacketTunnel(policy appleRuntimePolicy) bool {
	return policy.networkExtension && policy.packetTunnel
}

var easyTierPlaceholderRule = deviationRule{
	field:     "proxies",
	ruleScan:  true,
	category:  deviationForced,
	effective: "the node stands as a reject placeholder with the same name: it keeps its place in every group and rule, and every connection through it is refused",
	reason: "EasyTier is not built into the iPhone, iPad and Apple TV cores: its engine runs a " +
		"WebAssembly interpreter whose memory exceeds what the tunnel is allowed to use",
	source: "cmd/build_libbox/main.go notMacosTags carries no_easytier; adapter/outbound/easytier_stub.go; " +
		"iPad Pro (iPad14,5) measurement 2026-09-16: about 190 MiB of live Go heap after one engine start, " +
		"against the 50 MiB budget an Apple packet tunnel is killed at",
	recoverable: false,
	alternative: "use the node from the Mac app, or pick another node on this device",
	applies:     easyTierWalledProfile,
	mechanism: "the mobile slices are compiled with the no_easytier build tag, under which adapter/outbound/easytier_stub.go " +
		"constructs a Reject outbound carrying the node's name; the engine, its WebAssembly module and wazero are not linked",
}

var deviationRules = []deviationRule{
	{
		field:       "tproxy-port",
		category:    deviationUnavailable,
		effective:   "no transparent-proxy listener is opened",
		reason:      "transparent proxying is a Linux-only facility; the core itself reports it as unsupported on this platform",
		source:      "upstream listener/tproxy/setsockopt_other.go; iPhoneOS SDK netinet/in.h has no IP_TRANSPARENT",
		recoverable: false,
		mechanism:   "transparent proxying needs Linux netfilter; upstream's own non-Linux build answers \"not supported on current platform\"",
	},
	{
		field:       "redir-port",
		category:    deviationUnavailable,
		effective:   "no redirect listener is opened",
		reason:      "the redirect listener needs a system facility that an app on Apple is not allowed to open, and a firewall rule the app is not allowed to install",
		source:      "upstream listener/redir/tcp_darwin.go; /System/Library/Sandbox/Profiles/application.sb",
		recoverable: false,
		mechanism:   "upstream's darwin implementation reads the original destination from /dev/pf with a DIOCNATLOOK ioctl, which an App Sandbox cannot open, and installing the pf redirect rule it depends on needs root",
	},
	{
		field:       "dns.listen-routing-mark",
		category:    deviationUnavailable,
		effective:   "the mark is not applied",
		reason:      "socket marks are a Linux facility and do not exist on Apple",
		source:      "iPhoneOS SDK sys/socket.h defines no SO_MARK",
		recoverable: false,
		mechanism:   "SO_MARK is a Linux socket option and does not exist on Darwin",
	},
	{
		field:       "external-controller-routing-mark",
		category:    deviationUnavailable,
		effective:   "the mark is not applied",
		reason:      "socket marks are a Linux facility and do not exist on Apple",
		source:      "iPhoneOS SDK sys/socket.h defines no SO_MARK",
		recoverable: false,
		mechanism:   "SO_MARK is a Linux socket option and does not exist on Darwin",
	},
	{
		field:     "external-controller-pipe",
		category:  deviationUnavailable,
		effective: "no pipe is opened",
		reason: "a named pipe is a Windows facility; upstream requires the address to start " +
			"with \\\\.\\pipe\\ and has no Darwin implementation",
		source:      "upstream hub/route/server.go:308",
		recoverable: false,
	},
	{
		field:     "allow-lan",
		category:  deviationStripped,
		effective: "the configured listener stays on 127.0.0.1 instead of every interface",
		reason:    "local-network sharing is turned off in the app, and that switch overrides what the configuration asks for",
		source: "listener/listener.go:709-718 genAddr binds \":port\" when allow-lan is true and " +
			"127.0.0.1 when it is not; bind/clash/allow_lan_gate.go holds the app's switch",
		recoverable: false,
		alternative: "turn local-network sharing back on in the app; the configured value is honoured from the next reload",
		applies: func(policy appleRuntimePolicy) bool {
			return policy.networkExtension
		},
		forcedValue: "false",
		condition:   deviationConditionLANSharingOff,
	},
	{
		field:     "rules",
		ruleScan:  true,
		ruleKind:  "UID",
		category:  deviationUnavailable,
		effective: "UID rules are removed; a logic rule carrying a UID branch is removed whole",
		reason: "UID names a socket owner this platform does not expose, and the core's own rule " +
			"constructor refuses to build it here, so keeping the rule would fail the entire " +
			"configuration rather than simply never matching",
		source: "upstream rules/common/uid.go gates NewUid on GOOS linux/android/darwin; " +
			"rules/logic/logic.go parsePayload returns on the first branch that fails to construct",
		recoverable: false,
		applies: func(policy appleRuntimePolicy) bool {
			return policy.networkExtension && !policy.processMetadata().resolves("UID")
		},
	},
	easyTierPlaceholderRule,
	xhttpTunnelReuseRule,
	{
		field:     "tun.route-address-set",
		category:  deviationUnavailable,
		effective: "the routes take effect: the named rule set is read and its addresses are written into route-address before the core starts; the set name itself is accepted and ignored, the same as on any other platform",
		reason:    "the named rule set is turned into plain addresses before the core starts, so the routes you meant do take effect; the set itself is a Linux firewall facility that Apple does not have",
		source: "bind/clash/config_finalize.go FinalizeForIOS expandRouteSet; sing-tun consumes the " +
			"field itself only in redirect_linux.go and redirect_nftables*.go, always through " +
			"autoRedirect, and upstream documentation says Linux only and requires nftables",
		recoverable: false,
		honouredBy:  "expansion",
		mechanism:   "the FIELD is a Linux forwarding-plane switch -- it adds prefixes to an nftables set so the host firewall can bypass the redirect -- but the INTENT behind it, which prefixes enter the tunnel, is expressible here and is honoured by expanding it",
	},
	{
		field:     "tun.route-exclude-address-set",
		category:  deviationUnavailable,
		effective: "the exclusions take effect: the named rule set is read and its addresses are written into route-exclude-address before the core starts; the set name itself is accepted and ignored, the same as on any other platform",
		reason:    "the named rule set is turned into plain addresses before the core starts, so the routes you meant do take effect; the set itself is a Linux firewall facility that Apple does not have",
		source: "bind/clash/config_finalize.go FinalizeForIOS expandRouteSet; sing-tun consumes the " +
			"field itself only in redirect_linux.go and redirect_nftables*.go, always through " +
			"autoRedirect, and upstream documentation says Linux only and requires nftables",
		recoverable: false,
		honouredBy:  "expansion",
		mechanism:   "the FIELD is a Linux forwarding-plane switch -- it adds prefixes to an nftables set so the host firewall can bypass the redirect -- but the INTENT behind it, which prefixes enter the tunnel, is expressible here and is honoured by expanding it",
	},
	{
		field:       "ntp.write-to-system",
		category:    deviationForced,
		effective:   "false: the core keeps its own NTP offset and never sets the device clock",
		reason:      "only the system itself may set the device clock; an app or its extension cannot",
		source:      "man 2 settimeofday: \"Only the super-user may set the time of day\" (EPERM otherwise)",
		recoverable: false,
		forcedValue: "false",
		applies:     underNetworkExtension,
		mechanism:   "setting the system clock goes through settimeofday, which only the super-user may call; an app extension is not",
	},

	{
		field:       "routing-mark",
		category:    deviationUnavailable,
		effective:   "no mark is set on outbound sockets",
		reason:      "socket marks are a Linux facility and do not exist on Apple; the core itself reports it as unsupported here",
		source:      "upstream component/dialer/mark_nonlinux.go printMarkWarn; Darwin has no SO_MARK",
		recoverable: false,
		mechanism:   "SO_MARK is a Linux socket option; upstream's own non-Linux build warns \"Routing mark on socket is not supported on current platform\" and sets nothing",
	},

	{
		field:       "interface-name",
		category:    deviationStripped,
		effective:   "removed: the extension keeps the core's default interface on the current network",
		reason:      "the extension follows the current physical network and keeps the core's default interface on it as you move between Wi-Fi and cellular; a fixed top-level name would pin it. A name written on a node is honoured, as upstream honours it",
		source:      "bind/clash/config_pipeline.go normalizeRawNetworkExtensionSurfaces; bind/clash/monitor.go",
		recoverable: false,
		applies:     underNetworkExtension,
		mechanism:   "The application maintains the default physical interface. The dialer honours a node's own interface-name; only the top-level default is supplied by the extension.",
	},

	{
		field:     "dns.enable",
		category:  deviationForced,
		effective: "true: the core serves DNS for the queries the tunnel captures",
		reason: "an Apple packet tunnel always captures port 53; with dns.enable false the core " +
			"serves nothing and every captured query answers SERVFAIL, so the tunnel would " +
			"start and resolve nothing",
		source:          "upstream config/config.go DefaultRawConfig has DNS.Enable false",
		recoverable:     false,
		applies:         underNetworkExtension,
		upstreamDefault: "false",
		forcedValue:     "true",
	},
	{
		field:     "find-process-mode",
		category:  deviationForced,
		effective: "off: no rule is matched against the owning process, and PROCESS-*/UID rules evaluate against empty metadata",
		reason: "an app extension cannot enumerate other processes, so a lookup would fail on " +
			"every connection rather than some; the rules themselves are kept and behave " +
			"exactly as they do with find-process-mode off",
		source:          "upstream config/config.go DefaultRawConfig has FindProcessMode strict; bind/clash/config_pipeline.go normalizeRawNetworkExtensionSurfaces",
		recoverable:     false,
		applies:         func(policy appleRuntimePolicy) bool { return !policy.processMetadata().processPath },
		upstreamDefault: "strict",
		forcedValue:     "off",
	},
	{
		field:     "profile.store-fake-ip",
		category:  deviationForced,
		effective: "true: fake-ip mappings are written to disk so they survive an extension restart",
		reason: "an Apple packet tunnel is restarted by the system far more often than a desktop " +
			"process is, and a fresh in-memory pool hands out the same fake addresses again to " +
			"other domains while apps still hold the old ones; an explicit true or false is " +
			"always honoured",
		source:          "bind/clash/config_pipeline.go applyAppleDefaults (the typed-probe guard); upstream config/config.go DefaultRawConfig has StoreFakeIP false",
		recoverable:     true,
		alternative:     "write profile.store-fake-ip explicitly -- any value you set is kept",
		upstreamDefault: "false",
		defaultOnly:     true,
		forcedValue:     "true",
	},
	{
		field:     "unified-delay",
		category:  deviationForced,
		effective: "true: a probe reports the second, comparable round trip instead of billing the whole cold start to whichever proxy was measured first",
		reason: "upstream defaults unified-delay off, so the first probe of a proxy pays " +
			"TCP, TLS and the protocol handshake while the next one does not, and numbers " +
			"cannot be compared across proxies or protocols; an explicit true or false is " +
			"always honoured",
		source:          "bind/clash/config_pipeline.go applyAppleDefaults (the typed-probe guard); upstream config/config.go DefaultRawConfig has UnifiedDelay false",
		recoverable:     true,
		alternative:     "write unified-delay explicitly -- any value you set is kept",
		upstreamDefault: "false",
		defaultOnly:     true,
		forcedValue:     "true",
	},
	{
		field:     "tun.stack",
		category:  deviationForced,
		effective: "gvisor: a file that names no stack runs gvisor; system and mixed also run as gvisor while Include All Networks is on; a written gvisor or mips runs as written",
		reason:    tunIncludeAllNetworks,
		source: "bind/clash/config_pipeline.go applyAppleDefaults; bind/clash/override.go overrideTunForIOS; " +
			"third_party/sing-tun/stack.go ErrIncludeAllNetworks; NETunnelProviderProtocol.includeAllNetworks; " +
			"upstream config/config.go DefaultRawConfig has TunMips",
		recoverable:            true,
		alternative:            "write tun.stack (mips is kept as written); for system or mixed, turn Include All Networks off in the tunnel settings",
		applies:                underPacketTunnel,
		condition:              deviationConditionIncludeAllNetworks,
		upstreamDefault:        "mips",
		forcedValue:            "gvisor",
		forcedFrom:             []string{"system", "mixed"},
		unwrittenUnconditional: true,
		mechanism:              tunIncludeAllNetworksMechanism,
	},
	{
		field:       "tun.enable",
		category:    deviationForced,
		effective:   "true: the extension is a packet tunnel, so it always carries a tun",
		reason:      tunPacketTunnelShape,
		source:      "bind/clash/service.go ensureTunEnabled",
		recoverable: false,
		applies:     underPacketTunnel,
		forcedValue: "true",
		mechanism:   tunPacketTunnelShapeMechanism,
	},
	{
		field:       "tun.device",
		category:    deviationForced,
		effective:   "clash-packet-flow, this product's bridge",
		reason:      "on Apple the tunnel is handed to the core by the system, not opened by name, so there is no device to name",
		source:      "bind/clash/override.go overrideTunForIOS; Apple NEPacketTunnelProvider.packetFlow",
		recoverable: false,
		applies:     underPacketTunnel,
		forcedValue: "clash-packet-flow",
		mechanism:   "the extension is handed an NEPacketTunnelFlow rather than a utun descriptor, so a device name has nothing to name",
	},
	{
		field:       "tun.auto-route",
		category:    deviationForced,
		effective:   "false: Swift installs the routes",
		reason:      tunRoutingIsApples,
		source:      "bind/clash/override.go overrideTunForIOS; Apple NEPacketTunnelNetworkSettings",
		recoverable: false,
		alternative: "tun.route-address and tun.route-exclude-address ARE honoured, and become the routes the extension installs",
		applies:     underPacketTunnel,
		forcedValue: "false",
		mechanism:   tunRoutingIsApplesMechanism,
	},
	{
		field:       "tun.dns-mode",
		category:    deviationForced,
		effective:   "not set: the app sets this device's DNS to the tunnel",
		reason:      "on Apple the tunnel's DNS is set by the app's network settings, not by the core, so whether the core sets it has nothing to choose",
		source:      "bind/clash/override.go overrideTunForIOS; Apple NEPacketTunnelNetworkSettings.dnsSettings",
		recoverable: false,
		applies:     underPacketTunnel,
		mechanism:   "sing-tun's configureDNS registers the tunnel address as the system DNS only for a utun it opened itself; the extension hands it a descriptor and installs NEDNSSettings itself (TunOptions.GetDNSServerAddress)",
	},
	{
		field:       "tun.auto-detect-interface",
		category:    deviationForced,
		effective:   "false: the extension decides its own egress interface",
		reason:      tunRoutingIsApples,
		source:      "bind/clash/override.go overrideTunForIOS; Apple NEPacketTunnelNetworkSettings",
		recoverable: false,
		applies:     underPacketTunnel,
		forcedValue: "false",
		mechanism:   tunRoutingIsApplesMechanism,
	},
	{
		field:       "tun.gso",
		category:    deviationForced,
		effective:   "false",
		reason:      tunOffloadBridge,
		source:      "bind/clash/override.go overrideTunForIOS",
		recoverable: false,
		applies:     underPacketTunnel,
		forcedValue: "false",
		mechanism:   tunOffloadBridgeMechanism,
	},
	{
		field:       "tun.gso-max-size",
		category:    deviationForced,
		effective:   "0, following gso",
		reason:      tunOffloadBridge,
		source:      "bind/clash/override.go overrideTunForIOS",
		recoverable: false,
		applies:     underPacketTunnel,
		forcedValue: "0",
		mechanism:   tunOffloadBridgeMechanism,
	},
	{
		field:       "tun.recvmsgx",
		category:    deviationForced,
		effective:   "false: the tunnel uses its normal data path",
		reason:      tunBatchIOBridge,
		source:      "bind/clash/override.go overrideTunForIOS; upstream sing-tun recvmsg_x is the batched utun-fd read path, not a socket option",
		recoverable: false,
		applies:     underPacketTunnel,
		forcedValue: "false",
		mechanism:   tunBatchIOBridgeMechanism,
	},
	{
		field:       "tun.sendmsgx",
		category:    deviationForced,
		effective:   "false: the tunnel uses its normal data path",
		reason:      tunBatchIOBridge,
		source:      "bind/clash/override.go overrideTunForIOS; upstream sing-tun sendmsg_x is the batched utun-fd write path, not a socket option",
		recoverable: false,
		applies:     underPacketTunnel,
		forcedValue: "false",
		mechanism:   tunBatchIOBridgeMechanism,
	},
	{
		field:     "tun.disable-icmp-forwarding",
		category:  deviationForced,
		effective: "true: the core answers pings itself instead of forwarding them",
		reason: "forwarding ICMP needs a raw socket, which no unprivileged Apple process can " +
			"open; ping still answers, but the latency it shows is this device's, not the route's",
		source:      "bind/clash/override.go overrideTunForIOS; listener/sing_tun/prepare.go",
		recoverable: false,
		applies:     underPacketTunnel,
		forcedValue: "true",
	},
	{
		field:       "tun.include-interface",
		category:    deviationUnavailable,
		effective:   "kept, and ignored: nothing on Apple reads it",
		reason:      tunAutoRouteFilter,
		source:      "third_party/sing-tun/tun_linux.go, redirect_nftables_rules.go and redirect_iptables.go are the only readers; every other platform accepts the field and ignores it",
		recoverable: false,
		applies:     underPacketTunnel,
		mechanism:   tunAutoRouteFilterMechanism,
	},
	{
		field:       "tun.exclude-interface",
		category:    deviationUnavailable,
		effective:   "kept, and ignored: nothing on Apple reads it",
		reason:      tunAutoRouteFilter,
		source:      "third_party/sing-tun/tun_linux.go, redirect_nftables_rules.go and redirect_iptables.go are the only readers; every other platform accepts the field and ignores it",
		recoverable: false,
		applies:     underPacketTunnel,
		mechanism:   tunAutoRouteFilterMechanism,
	},
	{
		field:       "tun.include-uid",
		category:    deviationUnavailable,
		effective:   "kept, and ignored: nothing on Apple reads it",
		reason:      tunAutoRouteFilter,
		source:      "third_party/sing-tun/tun_linux.go, redirect_nftables_rules.go and redirect_iptables.go are the only readers; every other platform accepts the field and ignores it",
		recoverable: false,
		applies:     underPacketTunnel,
		mechanism:   tunAutoRouteFilterMechanism,
	},
	{
		field:       "tun.include-uid-range",
		category:    deviationUnavailable,
		effective:   "kept, and ignored: nothing on Apple reads it",
		reason:      tunAutoRouteFilter,
		source:      "third_party/sing-tun/tun_linux.go, redirect_nftables_rules.go and redirect_iptables.go are the only readers; every other platform accepts the field and ignores it",
		recoverable: false,
		applies:     underPacketTunnel,
		mechanism:   tunAutoRouteFilterMechanism,
	},
	{
		field:       "tun.exclude-uid",
		category:    deviationUnavailable,
		effective:   "kept, and ignored: nothing on Apple reads it",
		reason:      tunAutoRouteFilter,
		source:      "third_party/sing-tun/tun_linux.go, redirect_nftables_rules.go and redirect_iptables.go are the only readers; every other platform accepts the field and ignores it",
		recoverable: false,
		applies:     underPacketTunnel,
		mechanism:   tunAutoRouteFilterMechanism,
	},
	{
		field:       "tun.exclude-uid-range",
		category:    deviationUnavailable,
		effective:   "kept, and ignored: nothing on Apple reads it",
		reason:      tunAutoRouteFilter,
		source:      "third_party/sing-tun/tun_linux.go, redirect_nftables_rules.go and redirect_iptables.go are the only readers; every other platform accepts the field and ignores it",
		recoverable: false,
		applies:     underPacketTunnel,
		mechanism:   tunAutoRouteFilterMechanism,
	},
	{
		field:       "tun.exclude-src-port",
		category:    deviationUnavailable,
		effective:   "kept, and ignored: nothing on Apple reads it",
		reason:      tunAutoRouteFilter,
		source:      "third_party/sing-tun/tun_linux.go, redirect_nftables_rules.go and redirect_iptables.go are the only readers; every other platform accepts the field and ignores it",
		recoverable: false,
		applies:     underPacketTunnel,
		mechanism:   tunAutoRouteFilterMechanism,
	},
	{
		field:       "tun.exclude-src-port-range",
		category:    deviationUnavailable,
		effective:   "kept, and ignored: nothing on Apple reads it",
		reason:      tunAutoRouteFilter,
		source:      "third_party/sing-tun/tun_linux.go, redirect_nftables_rules.go and redirect_iptables.go are the only readers; every other platform accepts the field and ignores it",
		recoverable: false,
		applies:     underPacketTunnel,
		mechanism:   tunAutoRouteFilterMechanism,
	},
	{
		field:       "tun.exclude-dst-port",
		category:    deviationUnavailable,
		effective:   "kept, and ignored: nothing on Apple reads it",
		reason:      tunAutoRouteFilter,
		source:      "third_party/sing-tun/tun_linux.go, redirect_nftables_rules.go and redirect_iptables.go are the only readers; every other platform accepts the field and ignores it",
		recoverable: false,
		applies:     underPacketTunnel,
		mechanism:   tunAutoRouteFilterMechanism,
	},
	{
		field:       "tun.exclude-dst-port-range",
		category:    deviationUnavailable,
		effective:   "kept, and ignored: nothing on Apple reads it",
		reason:      tunAutoRouteFilter,
		source:      "third_party/sing-tun/tun_linux.go, redirect_nftables_rules.go and redirect_iptables.go are the only readers; every other platform accepts the field and ignores it",
		recoverable: false,
		applies:     underPacketTunnel,
		mechanism:   tunAutoRouteFilterMechanism,
	},
	{
		field:       "tun.include-mac-address",
		category:    deviationUnavailable,
		effective:   "kept, and ignored: nothing on Apple reads it",
		reason:      tunAutoRouteFilter,
		source:      "third_party/sing-tun/tun_linux.go, redirect_nftables_rules.go and redirect_iptables.go are the only readers; every other platform accepts the field and ignores it",
		recoverable: false,
		applies:     underPacketTunnel,
		mechanism:   tunAutoRouteFilterMechanism,
	},
	{
		field:       "tun.exclude-mac-address",
		category:    deviationUnavailable,
		effective:   "kept, and ignored: nothing on Apple reads it",
		reason:      tunAutoRouteFilter,
		source:      "third_party/sing-tun/tun_linux.go, redirect_nftables_rules.go and redirect_iptables.go are the only readers; every other platform accepts the field and ignores it",
		recoverable: false,
		applies:     underPacketTunnel,
		mechanism:   tunAutoRouteFilterMechanism,
	},
	{
		field:       "tun.mtu",
		category:    deviationForced,
		effective:   "the MTU the extension selected at startup",
		reason:      "the tunnel can only use one packet size, and the app and the core have to agree on it, so it is chosen once at startup; a value written here is not used, and the size that is used is the one both sides agreed on, so nothing is missing",
		source:      "bind/clash/override.go overrideTunForIOS; TunOptions.GetMTU",
		recoverable: false,
		applies:     underPacketTunnel,
		mechanism:   "the core and the Network Extension have to agree on one number -- Swift reads it back through TunOptions.GetMTU and installs it on NEPacketTunnelNetworkSettings -- so a value that reached only one of the two would describe a link neither side is running",
	},
	{
		field:       "geo-auto-update",
		category:    deviationForced,
		effective:   "the extension never downloads geo data itself; the app does, and hands the files to the core",
		reason:      "the app downloads geo data following geo-auto-update, geo-update-interval and geox-url in this file, and hands the files to the core; only the extension's own downloader is off",
		source:      "bind/clash/override.go",
		recoverable: false,
		forcedValue: "false",
		mechanism:   "the download moves from the extension to the app; the app reads the file's geo-auto-update, geo-update-interval and geox-url (GeoResources), so the reader's values are the ones that run -- only where the fetch happens differs from upstream",
	},
	{
		field:       "geodata-loader",
		category:    deviationForced,
		effective:   "memconservative: geo data is streamed rather than held decoded",
		reason:      "this core measured a 72.7 MiB peak compiling geosite, which a packet tunnel cannot afford; note that no Apple document states a memory ceiling",
		source:      "bind/clash/override.go; measured in this repository, not an Apple source",
		recoverable: false,
		forcedValue: "memconservative",
		applies:     func(policy appleRuntimePolicy) bool { return policy.memoryConservativeGeodata },
	},
	{
		field:       "geo-update-interval",
		category:    deviationUnavailable,
		effective:   "used by the app, which schedules the download; the extension has no downloader of its own",
		reason:      "the app downloads geo data on this interval when geo-auto-update is on, and hands the files to the core",
		source:      "bind/clash/override.go; see geo-auto-update",
		recoverable: false,
	},
	{
		field:       "tun.auto-redirect",
		category:    deviationUnavailable,
		effective:   "accepted and ignored, the same as on any other platform",
		reason:      "this configures a Linux-only part of the system that Apple does not have; the core accepts it and does nothing with it, exactly as it does on any non-Linux platform",
		source:      "sing-tun consumes it only in tun_linux.go and the redirect_nftables/iptables files, all Linux forwarding plane",
		recoverable: false,
		mechanism:   "this configures the Linux forwarding plane (nftables/iptables/iproute2), which no Apple platform has",
	},
	{
		field:       "tun.auto-redirect-input-mark",
		category:    deviationUnavailable,
		effective:   "accepted and ignored, the same as on any other platform",
		reason:      "this configures a Linux-only part of the system that Apple does not have; the core accepts it and does nothing with it, exactly as it does on any non-Linux platform",
		source:      "sing-tun consumes it only in tun_linux.go and the redirect_nftables/iptables files, all Linux forwarding plane",
		recoverable: false,
		mechanism:   "this configures the Linux forwarding plane (nftables/iptables/iproute2), which no Apple platform has",
	},
	{
		field:       "tun.auto-redirect-output-mark",
		category:    deviationUnavailable,
		effective:   "accepted and ignored, the same as on any other platform",
		reason:      "this configures a Linux-only part of the system that Apple does not have; the core accepts it and does nothing with it, exactly as it does on any non-Linux platform",
		source:      "sing-tun consumes it only in tun_linux.go and the redirect_nftables/iptables files, all Linux forwarding plane",
		recoverable: false,
		mechanism:   "this configures the Linux forwarding plane (nftables/iptables/iproute2), which no Apple platform has",
	},
	{
		field:       "tun.auto-redirect-iproute2-fallback-rule-index",
		category:    deviationUnavailable,
		effective:   "accepted and ignored, the same as on any other platform",
		reason:      "this configures a Linux-only part of the system that Apple does not have; the core accepts it and does nothing with it, exactly as it does on any non-Linux platform",
		source:      "sing-tun consumes it only in tun_linux.go and the redirect_nftables/iptables files, all Linux forwarding plane",
		recoverable: false,
		mechanism:   "this configures the Linux forwarding plane (nftables/iptables/iproute2), which no Apple platform has",
	},
	{
		field:       "tun.iproute2-table-index",
		category:    deviationUnavailable,
		effective:   "accepted and ignored, the same as on any other platform",
		reason:      "this configures a Linux-only part of the system that Apple does not have; the core accepts it and does nothing with it, exactly as it does on any non-Linux platform",
		source:      "sing-tun consumes it only in tun_linux.go and the redirect_nftables/iptables files, all Linux forwarding plane",
		recoverable: false,
		mechanism:   "this configures the Linux forwarding plane (nftables/iptables/iproute2), which no Apple platform has",
	},
	{
		field:       "tun.iproute2-rule-index",
		category:    deviationUnavailable,
		effective:   "accepted and ignored, the same as on any other platform",
		reason:      "this configures a Linux-only part of the system that Apple does not have; the core accepts it and does nothing with it, exactly as it does on any non-Linux platform",
		source:      "sing-tun consumes it only in tun_linux.go and the redirect_nftables/iptables files, all Linux forwarding plane",
		recoverable: false,
		mechanism:   "this configures the Linux forwarding plane (nftables/iptables/iproute2), which no Apple platform has",
	},
	{
		field:       "iptables",
		category:    deviationUnavailable,
		effective:   "accepted and ignored, the same as on any other platform",
		reason:      "this configures a Linux-only part of the system that Apple does not have; the core accepts it and does nothing with it, exactly as it does on any non-Linux platform",
		source:      "sing-tun consumes it only in tun_linux.go and the redirect_nftables/iptables files, all Linux forwarding plane",
		recoverable: false,
		mechanism:   "this configures the Linux forwarding plane (nftables/iptables/iproute2), which no Apple platform has",
	},
	{
		field:       "tun.include-package",
		category:    deviationUnavailable,
		effective:   "accepted and ignored, the same as on any other platform",
		reason:      "this names Android packages or users, which no Apple platform can resolve",
		source:      "resolving a package name to a UID exists only in sing-tun's packages_android.go; every other platform gets the packages_stub.go stub",
		recoverable: false,
	},
	{
		field:       "tun.exclude-package",
		category:    deviationUnavailable,
		effective:   "accepted and ignored, the same as on any other platform",
		reason:      "this names Android packages or users, which no Apple platform can resolve",
		source:      "resolving a package name to a UID exists only in sing-tun's packages_android.go; every other platform gets the packages_stub.go stub",
		recoverable: false,
	},
	{
		field:       "tun.include-android-user",
		category:    deviationUnavailable,
		effective:   "accepted and ignored, the same as on any other platform",
		reason:      "this names Android packages or users, which no Apple platform can resolve",
		source:      "resolving a package name to a UID exists only in sing-tun's packages_android.go; every other platform gets the packages_stub.go stub",
		recoverable: false,
	},
	{
		field:       "clash-for-android",
		category:    deviationUnavailable,
		effective:   "accepted and ignored, the same as on any other platform",
		reason:      "this names Android packages or users, which no Apple platform can resolve",
		source:      "resolving a package name to a UID exists only in sing-tun's packages_android.go; every other platform gets the packages_stub.go stub",
		recoverable: false,
	},
}

func collectConfigDeviations(mergedYAML string, policy appleRuntimePolicy) ([]configDeviation, error) {
	var root map[string]any
	if err := yaml.Unmarshal(readOnlyBytes(mergedYAML), &root); err != nil {
		return nil, err
	}
	if err := documentRuleIndexError(root); err != nil {
		return nil, err
	}
	return configDeviationRows(root, policy), nil
}

func deviationDocumentOf(root map[string]any) map[string]any {
	if root == nil {
		return nil
	}
	kept := make(map[string]any)
	keep := func(key string) {
		if value, present := root[key]; present {
			kept[key] = value
		}
	}
	for i := range deviationRules {
		top, _, _ := strings.Cut(deviationRules[i].field, ".")
		keep(top)
	}
	keep("rules")
	keep("x-clash-rule-index")
	keep("sub-rules")
	if proxies, isList := root["proxies"].([]any); isList {
		entries := make([]any, len(proxies))
		for index, entry := range proxies {
			if proxy, isMap := entry.(map[string]any); isMap && isEasyTierProxyType(proxy) {
				entries[index] = map[string]any{"type": proxy["type"], "name": proxy["name"]}
			} else if isMap && isXHTTPReuseDefaulted(proxy) {
				entries[index] = xhttpReuseKept(proxy)
			}
		}
		kept["proxies"] = entries
	}
	if library, isMap := root["x-clash-node-library"].(map[string]any); isMap {
		if defaulted, recorded := library["xhttp-reuse-defaulted"]; recorded {
			kept["x-clash-node-library"] = map[string]any{"xhttp-reuse-defaulted": defaulted}
		}
	}
	return kept
}

func configDeviationRows(root map[string]any, policy appleRuntimePolicy) []configDeviation {
	deviations := make([]configDeviation, 0)
	for _, rule := range deviationRules {
		if rule.ruleScan {
			continue
		}
		given, written := lookupYAMLPath(root, rule.field)
		if !rule.activeFor(policy, written) {
			continue
		}
		if rule.defaultOnly && written {
			continue
		}
		if written && rule.forcedValue != "" && given == rule.forcedValue {
			continue
		}
		if written && len(rule.forcedFrom) > 0 && !slices.ContainsFunc(rule.forcedFrom, func(value string) bool {
			return strings.EqualFold(value, given)
		}) {
			continue
		}
		if written && rule.withheld {
			given = deviationValueWithheld
		}
		upstreamDefault := ""
		if !written {
			if rule.upstreamDefault == "" {
				continue
			}
			given = "not set (core default: " + rule.upstreamDefault + ")"
			upstreamDefault = rule.upstreamDefault
		}
		deviations = append(deviations, configDeviation{
			Field:           rule.field,
			Given:           given,
			Effective:       rule.effective,
			Category:        rule.category,
			Reason:          rule.reason,
			Source:          rule.source,
			Recoverable:     rule.recoverable,
			Alternative:     rule.alternative,
			Mechanism:       rule.mechanism,
			Written:         written,
			UpstreamDefault: upstreamDefault,
			Honoured:        rule.honouredBy != "",
		})
	}
	deviations = append(deviations, ownerMetadataRuleDeviations(root, policy)...)
	deviations = append(deviations, easyTierPlaceholderDeviations(root, policy)...)
	deviations = append(deviations, xhttpTunnelReuseDeviations(root, policy)...)
	return deviations
}

func ownerMetadataRuleDeviations(root map[string]any, policy appleRuntimePolicy) []configDeviation {
	if !policy.networkExtension {
		return nil
	}
	capability := policy.processMetadata()

	reported := make([]configDeviation, 0)
	inertKinds := make(map[string]int)
	firstInert := make(map[string]string)
	eachDocumentRuleLine(root, func(index int, text string) {
		kind, _ := splitRuleKindAndPattern(text)
		if matchesMetadataRuleKindName(kind) == "" || capability.resolves(kind) {
			return
		}
		switch ownerMetadataRuleEffect(text) {
		case RuleEffectMatchesEverything:
			reported = append(reported, configDeviation{
				Field:     fmt.Sprintf("rules[%d]", index),
				Given:     text,
				Effective: "this rule matches every connection on this platform, with its action unchanged",
				Category:  deviationUnavailable,
				Effect:    RuleEffectMatchesEverything,
				Reason: "the pattern matches an empty process name, and this platform supplies " +
					"none, so a rule written to single out one process is now the broadest rule " +
					"in the file",
				Source:      "upstream rules/common/process.go Match compares the pattern against metadata.Process, which no Apple packet tunnel populates",
				Recoverable: true,
				Written:     true,
				RuleKind:    kind,
				Alternative: "anchor the pattern so it cannot match an empty name, or remove the rule",
			})
		case RuleEffectNeverMatches:
			if _, seen := inertKinds[kind]; !seen {
				firstInert[kind] = fmt.Sprintf("rules[%d]", index)
			}
			inertKinds[kind]++
		}
	})
	for kind, count := range inertKinds {
		field := "rules"
		given := fmt.Sprintf("%d rule(s), first at %s", count, firstInert[kind])
		if count == 1 {
			given = firstInert[kind]
		}
		reported = append(reported, configDeviation{
			Field:       field,
			Given:       given,
			Effective:   "these rules never match on this platform; traffic falls through to the next rule",
			Category:    deviationUnavailable,
			Effect:      RuleEffectNeverMatches,
			Reason:      "the metadata they test is not available to an Apple packet tunnel, so the comparison never succeeds",
			Source:      "upstream rules/common Match reads metadata this platform does not populate; the rules are kept rather than removed so logic rules keep their executable branches",
			Recoverable: false,
			Written:     true,
			RuleKind:    kind,
		})
	}
	if !capability.resolves("UID") {
		if registration := deviationRuleByKind("UID"); registration != nil && registration.active(policy) {
			count, first := uidRuleOccurrences(root)
			if count > 0 {
				given := fmt.Sprintf("%d rule(s), first at %s", count, first)
				if count == 1 {
					given = first
				}
				reported = append(reported, configDeviation{
					Field:       registration.field,
					Given:       given,
					Effective:   registration.effective,
					Category:    registration.category,
					Reason:      registration.reason,
					Source:      registration.source,
					Recoverable: registration.recoverable,
					Alternative: registration.alternative,
					Mechanism:   registration.mechanism,
					Written:     true,
					RuleKind:    registration.ruleKind,
				})
			}
		}
	}
	sort.Slice(reported, func(i, j int) bool {
		if reported[i].Field != reported[j].Field {
			return reported[i].Field < reported[j].Field
		}
		return reported[i].RuleKind < reported[j].RuleKind
	})
	return reported
}

func deviationRuleByKind(kind string) *deviationRule {
	for i := range deviationRules {
		if deviationRules[i].ruleScan && deviationRules[i].ruleKind == kind {
			return &deviationRules[i]
		}
	}
	return nil
}

func deviationRuleByField(field string) *deviationRule {
	for i := range deviationRules {
		if deviationRules[i].field == field {
			return &deviationRules[i]
		}
	}
	return nil
}

func uidRuleOccurrences(root map[string]any) (count int, first string) {
	scan := func(entries []any, location func(int) string) {
		for index, entry := range entries {
			text, isString := entry.(string)
			if !isString || !ruleCarriesUID(text) {
				continue
			}
			if count == 0 {
				first = location(index)
			}
			count++
		}
	}
	rules, _ := root["rules"].([]any)
	scan(rules, func(i int) string { return fmt.Sprintf("rules[%d]", i) })
	if ref, ok := documentRuleIndexRef(root); ok && len(rules) == 0 && len(ref.UIDRemoved) > 0 {
		if count == 0 {
			first = fmt.Sprintf("rules[%d]", ref.UIDRemoved[0])
		}
		count += len(ref.UIDRemoved)
	}
	if subRules, ok := root["sub-rules"].(map[string]any); ok {
		names := make([]string, 0, len(subRules))
		for name := range subRules {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			list, _ := subRules[name].([]any)
			scan(list, func(i int) string { return fmt.Sprintf("sub-rules.%s[%d]", name, i) })
		}
	}
	return count, first
}

func lookupYAMLPath(root map[string]any, path string) (string, bool) {
	current := any(root)
	for _, segment := range strings.Split(path, ".") {
		node, isMap := current.(map[string]any)
		if !isMap {
			return "", false
		}
		value, present := node[segment]
		if !present {
			return "", false
		}
		current = value
	}
	if current == nil {
		return "", false
	}
	return renderDeviationValue(current), true
}

const deviationValueWithheld = "set (value withheld)"

func renderDeviationValue(value any) string {
	switch typed := value.(type) {
	case string:
		if typed == "" {
			return `""`
		}
		return typed
	case []any:
		return fmt.Sprintf("%d entries", len(typed))
	case map[string]any:
		return fmt.Sprintf("%d keys", len(typed))
	default:
		return fmt.Sprintf("%v", typed)
	}
}

var publishedDeviations atomic.Pointer[publishedDeviationReport]

const (
	deviationEntryStart  = "start"
	deviationEntryReload = "reload"
)

type deviationDocumentIdentity struct {
	Bytes  int    `json:"bytes"`
	SHA256 string `json:"sha256"`
}

type publishedDeviationReport struct {
	Sequence   uint64
	Entry      string
	Document   deviationDocumentIdentity
	Deviations []configDeviation
}

var deviationPublishSequence atomic.Uint64

func publishDeviations(entry, content string, deviations []configDeviation) *publishedDeviationReport {
	sum := sha256.Sum256([]byte(content))
	report := &publishedDeviationReport{
		Sequence:   deviationPublishSequence.Add(1),
		Entry:      entry,
		Document:   deviationDocumentIdentity{Bytes: len(content), SHA256: hex.EncodeToString(sum[:])},
		Deviations: deviations,
	}
	publishedDeviations.Store(report)
	log.Infoln("[Apple] deviations published: entry=%s seq=%d document=%dB sha256=%s rows=%d",
		entry, report.Sequence, report.Document.Bytes, report.Document.SHA256[:16], len(deviations))
	for _, deviation := range deviations {
		log.Warnln("[Apple] deviation %s: given=%q effective=%q category=%s -- %s",
			deviation.Field, deviation.Given, deviation.Effective, deviation.Category, deviationWhy(deviation))
	}
	return report
}

func deviationWhy(deviation configDeviation) string {
	if deviation.Mechanism != "" {
		return deviation.Mechanism
	}
	return deviation.Reason
}

func loadPublishedDeviationReport() *publishedDeviationReport {
	return publishedDeviations.Load()
}

func loadPublishedDeviations() []configDeviation {
	if report := publishedDeviations.Load(); report != nil {
		return report.Deviations
	}
	return []configDeviation{}
}
