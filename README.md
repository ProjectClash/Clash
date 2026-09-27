<p align="center">
  <img src="https://clash.md/brand/clash-app-icon.png" width="128" height="128" alt="Clash">
</p>

# Clash

**Proxy core for Apple platforms · Based on mihomo**

English · [简体中文](README.zh-CN.md)

[![Website](https://img.shields.io/badge/Website-Official-2563EB)](https://clash.md/)
[![App Store Download](https://img.shields.io/badge/App_Store-Download-black?logo=apple&logoColor=white)](https://apps.apple.com/app/id6794257189)
[![Telegram Channel](https://img.shields.io/badge/Telegram-Channel-26A5E4?logo=telegram&logoColor=white)](https://t.me/clashbyclash)
[![Telegram Group](https://img.shields.io/badge/Telegram-Group-26A5E4?logo=telegram&logoColor=white)](https://t.me/+t__WNRvjUbk3M2Nl)

Clash is a proxy kernel based on **mihomo v1.19.31**, with Go bindings and build tooling for Apple applications on iOS, macOS and tvOS.

To install the official app, use the App Store link above. This repository is for developers building or integrating the kernel.

## Repository migration status

This is the new kernel repository under **Project Clash**. This first publication contains the English and Chinese READMEs; source code, build scripts, license files and SDK releases will follow.

The technical notes below use the Clash directory, module and SDK names planned for the source migration. Build commands apply after that rename is complete and the source and supporting files are available in this repository.

## Upstream and modifications

Clash is an independent derivative of [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo), based on [v1.19.31](https://github.com/MetaCubeX/mihomo/tree/v1.19.31), commit `ab405bad5beeeac8b003bb01f60f134f6df54471`. It is not affiliated with MetaCubeX. The upstream project asks unaffiliated downstream projects not to use “mihomo” in their names.

Kernel adaptations include Apple bindings, SDK build tooling and runtime integration. Source provenance, modification notes, contributor attribution and license notices will accompany the source migration. This README publication contains no source tree or historical commits.

The source uses GPL-3.0. `LICENSE`, `NOTICE` and `THIRD_PARTY_LICENSES.md` will accompany the source migration.

## Project repositories

| Repository | Contents |
| --- | --- |
| [Clash](https://github.com/ProjectClash/Clash) | Proxy kernel, Go bindings and Apple SDK build tools |
| [Clash-Client](https://github.com/ProjectClash/Clash-Client) | Native iOS, iPadOS, macOS and tvOS applications and extensions |

The upstream baseline version describes the proxy engine. It is separate from the App Store app version and the SDK release tag. Untagged source on `main` is pre-release; pin a specific revision when integrating it. Future SDK versions and downloads will be listed in [Releases](https://github.com/ProjectClash/Clash/releases). No SDK is included in this README publication.

The existing SDK packaging includes all five Apple slices, license notices and a source manifest. Supporting release files include the notices separately, the source archive for the embedded EasyTier core used by macOS, and `SHA256SUMS` for checking downloaded assets.

## Source layout (to be migrated)

- The mihomo-based proxy engine: protocol implementations, DNS, routing rules, proxy groups and providers.
- `bind/clash`: the API exposed to Apple applications through gomobile.
- `cmd/build_libbox`: SDK generation and platform packaging.
- `docs/config.yaml`: configuration reference included with the source.

An application supplies configuration, storage, the Network Extension integration and signing. Platform capabilities differ; a configuration accepted by the parser does not establish end-to-end support for every protocol or rule on every platform.

The iOS and tvOS SDK slices use `no_easytier` and do not include EasyTier. The macOS slice does not apply that exclusion. Platform permissions, TUN stacks and outbound implementations still determine what is available at runtime.

## Build the Apple SDK (after source migration)

Use macOS with the full Xcode installation and the iOS, macOS and tvOS SDKs. The previous source build was checked with Xcode 27.0; the renamed source will be validated when it is migrated. The binding module declares Go 1.25.0 and selects toolchain Go 1.26.6 in `bind/clash/go.mod`; allow Go to obtain that toolchain, or install it explicitly.

Once the source and relevant tags have been migrated, clone the repository and install the pinned gomobile tools:

```sh
git clone https://github.com/ProjectClash/Clash.git
cd Clash
go install github.com/sagernet/gomobile/cmd/gomobile@v0.1.13
go install github.com/sagernet/gomobile/cmd/gobind@v0.1.13
make lib_apple
```

The core version comes from `UPSTREAM_VERSION`, shipped with the source, so a source upgrade does not inherit an older SDK tag. The SDK release version still comes from a release tag at the current commit; ordinary source builds are labeled `dev-<commit>`.

The output is `Clash.xcframework`, containing five platform slices:

| Platform | Architectures |
| --- | --- |
| iOS device | arm64 |
| iOS Simulator | arm64, x86_64 |
| macOS | arm64, x86_64 |
| tvOS device | arm64 |
| tvOS Simulator | arm64, x86_64 |

The SDK framework is static: choose **Do Not Embed** when linking it directly, and link `libresolv`. An app and its extension can share a dynamic framework wrapping the static SDK to avoid packaging the kernel twice; the iOS and macOS Client projects use this arrangement. Use the generated headers for the API of your pinned revision. For a working application integration, see [Clash-Client](https://github.com/ProjectClash/Clash-Client).

## Development and feedback

For the root Go module:

```sh
go build ./...
go test ./...
```

The Apple binding has its own module and tests under `bind/clash`. An SDK build alone does not establish runtime behavior on a signed device.

Report kernel problems in this repository's [Issues](https://github.com/ProjectClash/Clash/issues). Include the source revision, platform, reproduction steps, expected behavior and observed result. Use a minimal sample configuration with secrets removed. For app interface or installation problems, use [Clash-Client Issues](https://github.com/ProjectClash/Clash-Client/issues).

Security reporting instructions will be provided in `SECURITY.md` with the source. Do not disclose sensitive security details in public issues.

## License and credits

Clash is based on [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo) and the work of its contributors. Clash is an independent project and is not affiliated with or endorsed by MetaCubeX.

The project source is licensed under [GPL-3.0](https://www.gnu.org/licenses/gpl-3.0.html). The complete license, attribution and dependency notices will accompany the source migration.
