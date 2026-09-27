<p align="center">
  <img src="https://clash.md/brand/clash-app-icon.png" width="128" height="128" alt="Clash">
</p>

# Clash

**Apple 代理内核 · 基于 mihomo**

[English](README.md) · 简体中文

[![官方网站](https://img.shields.io/badge/%E5%AE%98%E7%BD%91-%E8%AE%BF%E9%97%AE-2563EB)](https://clash.md/)
[![App Store 下载](https://img.shields.io/badge/App_Store-%E4%B8%8B%E8%BD%BD-black?logo=apple&logoColor=white)](https://apps.apple.com/app/id6794257189)
[![Telegram 交流群](https://img.shields.io/badge/Telegram-%E4%BA%A4%E6%B5%81%E7%BE%A4-26A5E4?logo=telegram&logoColor=white)](https://t.me/+t__WNRvjUbk3M2Nl)

Clash 是基于 **mihomo v1.19.31** 的代理内核，提供面向 Apple 应用的 Go 绑定与构建工具，支持 iOS、macOS 和 tvOS。

使用官方应用请点击顶部的 App Store 下载链接。本仓库面向构建或集成内核的开发者。

## 仓库迁移状态

本仓库是 **Project Clash** 组织下的内核新仓库。本次先发布中英文 README，源码、构建脚本、许可证文件及 SDK 发行版将后续同步。

以下技术说明统一采用源码迁移后的 Clash 目录、模块与 SDK 命名。构建命令需等源码完成配套改名并上传后，才能在本仓库使用。

## 上游与修改说明

Clash 是基于 [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo) 的独立衍生项目，上游基线为 [v1.19.31](https://github.com/MetaCubeX/mihomo/tree/v1.19.31)，提交为 `ab405bad5beeeac8b003bb01f60f134f6df54471`。本项目与 MetaCubeX 无隶属关系。上游要求无隶属关系的下游项目不要在项目名称中使用“mihomo”。

内核适配包括 Apple 绑定、SDK 构建工具与运行环境调整。源码同步时会一并提供上游来源、修改说明、贡献者署名和许可证声明；当前 README 发布不包含源码或历史提交。

源码采用 GPL-3.0 许可证。`LICENSE`、`NOTICE` 和 `THIRD_PARTY_LICENSES.md` 将随源码同步。

## 项目仓库

| 仓库 | 内容 |
| --- | --- |
| [Clash](https://github.com/ProjectClash/Clash) | 代理内核、Go 绑定与 Apple SDK 构建工具 |
| [Clash-Client](https://github.com/ProjectClash/Clash-Client) | iOS、iPadOS、macOS 和 tvOS 原生应用及扩展 |

上游基线版本表示代理引擎版本，与 App Store 应用版本、SDK 发布标签分别管理。`main` 上未打发布标签的源码按预发布版本管理；集成时请固定具体提交。后续 SDK 版本及下载将在[发行版页面](https://github.com/ProjectClash/Clash/releases)发布；本次 README 发布不包含 SDK。

SDK 的既有打包内容包括五个 Apple 平台切片、许可证声明和源码清单。配套发布文件包括独立的许可证压缩包、macOS 所用 EasyTier 内嵌内核的对应源码包，以及用于核对下载文件的 `SHA256SUMS`。

## 源码组成（待同步）

- 基于 mihomo 的代理引擎，包括协议实现、DNS、路由规则、代理组和资源提供者。
- `bind/clash`：通过 gomobile 暴露给 Apple 应用的接口。
- `cmd/build_libbox`：SDK 生成与平台打包工具。
- `docs/config.yaml`：随源码提供的配置参考。

应用负责提供配置、存储、Network Extension 接入和签名。不同平台的能力有所区别；配置能被解析，不代表所有协议和规则都已在每个平台完成端到端验证。

Apple SDK 的 iOS 和 tvOS 切片使用 `no_easytier`，不包含 EasyTier；macOS 切片未应用这一排除。平台权限、TUN 栈及出站实现仍会影响实际能力。

## 构建 Apple SDK（源码同步后）

需要 macOS、完整的 Xcode，以及 iOS、macOS、tvOS SDK。改名前的源码已使用 Xcode 27.0 验证，改名后的构建将在源码迁移时重新验证。绑定模块在 `bind/clash/go.mod` 中声明 Go 1.25.0，并选择 Go 1.26.6 工具链；请允许 Go 获取该工具链，或自行安装。

待源码与相关标签同步后，克隆仓库并安装固定版本的 gomobile 工具：

```sh
git clone https://github.com/ProjectClash/Clash.git
cd Clash
go install github.com/sagernet/gomobile/cmd/gomobile@v0.1.13
go install github.com/sagernet/gomobile/cmd/gobind@v0.1.13
make lib_apple
```

内核版本由随源码发布的 `UPSTREAM_VERSION` 指定，避免升级源码后误用较旧的 SDK 标签。SDK 发布版本仍由当前提交的发布标签决定；普通源码构建标为 `dev-<提交>`。

输出为 `Clash.xcframework`，包含五个平台切片：

| 平台 | 架构 |
| --- | --- |
| iOS 真机 | arm64 |
| iOS 模拟器 | arm64、x86_64 |
| macOS | arm64、x86_64 |
| tvOS 真机 | arm64 |
| tvOS 模拟器 | arm64、x86_64 |

SDK 是静态框架，直接链接时将嵌入选项设为 **Do Not Embed**，并链接 `libresolv`。应用和扩展可通过共享的动态框架封装它，避免重复打包内核；Client 的 iOS 和 macOS 工程已采用这种结构。具体接口以所固定提交生成的头文件为准。完整应用的接入方式可参考 [Clash-Client](https://github.com/ProjectClash/Clash-Client)。

## 开发与反馈

根目录 Go 模块可使用以下命令构建和测试：

```sh
go build ./...
go test ./...
```

Apple 绑定在 `bind/clash` 下有独立模块和测试。SDK 构建成功不代表签名真机上的运行行为已经验证。

内核问题请提交到本仓库的 [Issues](https://github.com/ProjectClash/Clash/issues)，附上源码提交、平台、复现步骤、预期行为与实际结果。配置示例应尽量精简，并移除密钥等敏感内容。应用界面或安装问题请提交到 [Clash-Client Issues](https://github.com/ProjectClash/Clash-Client/issues)。

安全报告方式将在 `SECURITY.md` 随源码同步；请勿在公开 Issue 中披露敏感细节。

## 许可证与致谢

Clash 基于 [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo) 及其贡献者的工作。Clash 是独立项目，与 MetaCubeX 没有隶属或背书关系。

项目源码采用 [GPL-3.0](https://www.gnu.org/licenses/gpl-3.0.html) 许可证。完整的许可证、署名和依赖声明将随源码同步。
