# Third-party licenses (Clash.xcframework)

> This document explains the load-bearing license families. Every packaged SDK
> additionally ships `THIRD_PARTY_LICENSES.zip`; its `INDEX.json` is generated
> from the exact production-tag package graph and contains every linked module,
> version/replacement, copied license file and SHA-256. Release packaging fails
> if a linked third-party module has no discoverable license text.

## Kernel & core forks

| Component | License | Notes |
|---|---|---|
| `github.com/metacubex/mihomo` | GPLv3 | The proxy kernel — makes the whole product GPLv3 |
| `github.com/metacubex/sing`, `sing-tun`, `sing-mux`, `sing-quic`, `sing-shadowsocks(2)`, `sing-shadowtls`, `sing-vmess`, `sing-wireguard` | GPLv3 (metacubex forks) | tun stack + protocol transports linked into the framework |
| `github.com/metacubex/tfo-go` | BSD-3 | TCP fast-open |
| `github.com/metacubex/gvisor` | Apache-2.0 / BSD | userspace TCP/IP stack (gVisor fork) |
| `github.com/metacubex/quic-go` | MIT | QUIC |
| `github.com/sagernet/sing-snell`, `github.com/sagernet/sing` | GPLv3 | Snell v6 nodes and listeners; linked by the Apple binding only |

## Protocol / crypto / util (representative)

- `github.com/sagernet/*` (sing ecosystem upstream where used) — mixed (mostly GPLv3/BSD).
- `golang.org/x/*` (net, sys, crypto, mobile) — BSD-3.
- `google.golang.org/protobuf` — BSD-3.
- `github.com/klauspost/compress`, `github.com/pierrec/lz4`, `github.com/ulikunitz/xz` — BSD.
- `github.com/miekg/dns` — BSD-3.
- Full list: `go.mod` / `go.sum` at the released commit.

## gomobile generator and generated runtime

- `github.com/sagernet/gomobile/cmd/gomobile` and `cmd/gobind` — BSD-style;
  generator commands executed at build time, not binaries linked into the SDK.
- gomobile's generated Objective-C/Go bridge runtime and glue — BSD-style;
  statically present in every framework slice. The product symbols include
  `go_seq_inc_ref`, `go_seq_dec_ref`, `GoSeqRef`, and `goSeqDictionary`, so the
  gomobile attribution travels with the distributed SDK even though the
  generator executables do not.

## sing-box reference and adapted code (GPLv3, SagerNet)

- `SagerNet/sing-box-for-apple`, `SagerNet/sing-box` — NE utun handoff + libbox API surface referenced.
- `SagerNet/sing-box/common/networkquality` at `4bccd6fae19526425acf76efc263333c7aea6fce` — HTTP network-quality algorithm adapted into `bind/clash/internal/networkquality` and statically linked; GPL-3.0-or-later.
- `SagerNet/sing-box/dns/transport/local/local_darwin.go` at `5ee65a5ca9e6a448a5fa2f47b55b51fe2fcf578d` — the mDNSResponder IPC client (framing, reply parsing, record assembly) adapted into `bind/clash/mdns_darwin.go` and statically linked; GPL-3.0-or-later. The wire protocol itself is Apple's, from its open-source mDNSResponder client stub; what is adapted here is the Go expression of it.
- `SagerNet/sing-box/dns/transport/local/systemconfig/source_darwin.go` at `5ee65a5ca9e6a448a5fa2f47b55b51fe2fcf578d` — the dns_configuration reader (packed DNSINFO layouts, dlsym lookup, scoped-then-unscoped selection) adapted into `bind/clash/system_resolver_dnsinfo_darwin.go` and statically linked; GPL-3.0-or-later.
- `SagerNet/sing-box/common/dialer/default.go` and `default_parallel_interface.go` at `5ee65a5ca9e6a448a5fa2f47b55b51fe2fcf578d` — the network_strategy multi-interface dial algorithm and its two timings adapted into `component/dialer/network_strategy.go` and statically linked; GPL-3.0-or-later.
- `SagerNet/sing-box-for-apple` at `8ce05ea68cd6fe8b7aa71e279c7404274b4c5d24` — referenced for the Network Extension's socket-scoping posture; no code adapted.

## Module scripts' DOM (the app and the network extension)

- The HTML Standard's named character references (`https://html.spec.whatwg.org/entities.json`, sha256 `d741d877ac77…`, fetched 2026-10-20) — carried as data in the Apple client's DOM parser that module scripts use. Copyright © WHATWG (Apple, Google, Mozilla, Microsoft); the Standard is CC BY 4.0, and portions incorporated into source code are licensed under the BSD 3-Clause License instead. Credited in the Apple client's third-party license list (`whatwg/html`). The parser, DOM and selector engine around it are this project's own code.

## Generate the authoritative complete bundle

```sh
go run ./cmd/package_licenses -output dist/THIRD_PARTY_LICENSES
```

Generated-runtime evidence for a release artifact:

```sh
nm -gU Clash.xcframework/ios-arm64/Clash.framework/Clash \
  | grep -E 'go_seq_(inc|dec)_ref|GoSeqRef|goSeqDictionary'
```

Net effect: because mihomo is GPLv3 and is statically linked, the combined
work is **GPLv3** regardless of the permissive licenses above.
