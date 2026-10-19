<p align="center">
  <img src="https://clash.md/brand/clash-app-icon.png" width="128" height="128" alt="Clash">
</p>

# Clash

English · [简体中文](README.zh-CN.md)

[![Website](https://img.shields.io/badge/Website-Official-2563EB)](https://clash.md/)
[![App Store Download](https://img.shields.io/badge/App_Store-Download-black?logo=apple&logoColor=white)](https://apps.apple.com/app/id6794257189)
[![Telegram Channel](https://img.shields.io/badge/Telegram-Channel-26A5E4?logo=telegram&logoColor=white)](https://t.me/clashbyclash)
[![Telegram Group](https://img.shields.io/badge/Telegram-Group-26A5E4?logo=telegram&logoColor=white)](https://t.me/+t__WNRvjUbk3M2Nl)

Clash is a proxy kernel based on **mihomo v1.19.32**, with Go bindings and build tooling for Apple applications. It produces `Clash.xcframework` for iOS, macOS and tvOS.

To install the official app, use the App Store link above. This repository is for developers building or integrating the kernel.

## Upstream history and modifications

Clash is an independent derivative of [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo), based on [v1.19.32](https://github.com/MetaCubeX/mihomo/tree/v1.19.32), commit `88dcbf7f1614a67c3b36b848ee3592dfa92ada36`. It is not affiliated with MetaCubeX. The upstream project asks unaffiliated downstream projects not to use “mihomo” in their names.

This repository retains the original mihomo commits and contributor identities. Its first source publication records the accumulated Clash adaptations in one commit, joining the existing README history with the official upstream baseline. Later changes are published as separate logical commits; stable upstream upgrades retain the official upstream commits as merge parents. Compare the upstream baseline with a Clash revision to inspect the Apple bindings, SDK build tools and kernel modifications. This initial publication does not reconstruct the development history of those adaptations.

The upstream GPL-3.0 license remains in [LICENSE](LICENSE). See [NOTICE](NOTICE) and [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md) for attribution and dependency licenses.

## Project repositories

| Repository | Contents |
| --- | --- |
| [Clash](https://github.com/ProjectClash/Clash) | Proxy kernel, Go bindings and Apple SDK build tools |
| [Clash-Adapter](https://github.com/ProjectClash/Clash-Adapter) | Swift packet-flow bridge and provider lifecycle components |
| [Clash-Client](https://github.com/ProjectClash/Clash-Client) | Native iOS, iPadOS, macOS and tvOS applications and extensions |

## Versions and downloads

| Component | Current reference |
| --- | --- |
| Upstream engine | mihomo **v1.19.32**, recorded in [`UPSTREAM_VERSION`](UPSTREAM_VERSION) |
| Released Apple SDK | [`v1.19.32-clash.3`](https://github.com/ProjectClash/Clash/releases/tag/v1.19.32-clash.3) |
| Client integration | Kernel and Adapter commits pinned in the Client's [`Dependencies.lock.json`](https://github.com/ProjectClash/Clash-Client/blob/main/Dependencies.lock.json) |

The upstream engine version, SDK release tag and App Store app versions are separate. Use a release tag to reproduce an SDK release; `main` can contain later changes. Client and Adapter source are currently published by commit, without their own release tags.

SDK downloads include all five Apple slices, license notices and a source manifest. Each release also provides the notices separately, the source archive for the embedded EasyTier core used by macOS, and `SHA256SUMS` for checking downloaded assets.

## What is included

- The mihomo-based proxy engine: protocol implementations, DNS, routing rules, proxy groups and providers.
- `bind/clash`: the API exposed to Apple applications through gomobile.
- `cmd/build_libbox`: SDK generation and platform packaging.
- [`docs/config.yaml`](docs/config.yaml): configuration reference included with the source.

An application supplies configuration, storage, the Network Extension integration and signing. Platform capabilities differ; a configuration accepted by the parser does not establish end-to-end support for every protocol or rule on every platform.

The iOS and tvOS SDK slices use `no_easytier` and do not include EasyTier. The macOS slice does not apply that exclusion. Platform permissions, TUN stacks and outbound implementations still determine what is available at runtime.

## Build the Apple SDK

Use macOS with the full Xcode installation and the iOS, macOS and tvOS SDKs. The binding module declares Go 1.26.0 and selects toolchain Go 1.26.9 in [`bind/clash/go.mod`](bind/clash/go.mod); allow Go to obtain that toolchain, or install it explicitly.

To build the current released SDK, clone the repository with its history and tags, check out the release, then install the pinned gomobile tools:

```sh
git clone https://github.com/ProjectClash/Clash.git
cd Clash
git checkout --detach v1.19.32-clash.3
go install github.com/sagernet/gomobile/cmd/gomobile@v0.1.13
go install github.com/sagernet/gomobile/cmd/gobind@v0.1.13
make lib_apple
```

Select the full Xcode installation as your active developer directory, rather than standalone Command Line Tools. If Xcode is installed at the standard path, you can set `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer` in your build environment.

The core version comes from `UPSTREAM_VERSION`, shipped with the source, so a source upgrade does not inherit an older SDK tag. The SDK release version comes from a release tag at the current commit; building an untagged revision instead produces `dev-<commit>`. Go dependencies are recorded in the root and binding module's `go.mod`/`go.sum` files; the SDK build uses both modules.

The output is `Clash.xcframework`, containing five platform slices:

| Platform | Architectures |
| --- | --- |
| iOS device | arm64 |
| iOS Simulator | arm64, x86_64 |
| macOS | arm64, x86_64 |
| tvOS device | arm64 |
| tvOS Simulator | arm64, x86_64 |

The SDK framework is static: choose **Do Not Embed** when linking it directly, and link `libresolv`. An app and its extension can share a dynamic framework wrapping the static SDK to avoid packaging the kernel twice; the iOS and macOS Client projects use this arrangement. Use the generated headers for the API of your pinned revision. The application source and build instructions are available in [Clash-Client](https://github.com/ProjectClash/Clash-Client). The Mac app's bundled controller helper is maintained in [Clash-Client/cli](https://github.com/ProjectClash/Clash-Client/tree/main/cli).

## Development and feedback

For the root Go module:

```sh
go build ./...
go test ./...
```

The Apple binding has its own module and tests under `bind/clash`. An SDK build alone does not establish runtime behavior on a signed device.

Report kernel problems in this repository's [Issues](https://github.com/ProjectClash/Clash/issues). Include the source revision, platform, reproduction steps, expected behavior and observed result. Use a minimal sample configuration with secrets removed. For app interface or installation problems, use [Clash-Client Issues](https://github.com/ProjectClash/Clash-Client/issues).

For security reports, follow [SECURITY.md](SECURITY.md).

## License and credits

Clash is based on [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo) and the work of its contributors. Clash is an independent project and is not affiliated with or endorsed by MetaCubeX.

The project is licensed under [GPL-3.0](LICENSE). See [NOTICE](NOTICE) and [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md) for attribution and dependency licenses.
