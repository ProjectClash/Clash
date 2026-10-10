<p align="center">
  <img src="https://clash.md/brand/clash-app-icon.png" width="128" height="128" alt="Clash">
</p>

# Clash

[English](README.md) · 简体中文

[![官方网站](https://img.shields.io/badge/%E5%AE%98%E7%BD%91-%E8%AE%BF%E9%97%AE-2563EB)](https://clash.md/)
[![App Store 下载](https://img.shields.io/badge/App_Store-%E4%B8%8B%E8%BD%BD-black?logo=apple&logoColor=white)](https://apps.apple.com/app/id6794257189)
[![Telegram 频道](https://img.shields.io/badge/Telegram-%E9%A2%91%E9%81%93-26A5E4?logo=telegram&logoColor=white)](https://t.me/clashbyclash)
[![Telegram 交流群](https://img.shields.io/badge/Telegram-%E4%BA%A4%E6%B5%81%E7%BE%A4-26A5E4?logo=telegram&logoColor=white)](https://t.me/+t__WNRvjUbk3M2Nl)

Clash 是基于 **mihomo v1.19.32** 的代理内核，提供面向 Apple 应用的 Go 绑定与构建工具，可生成支持 iOS、macOS 和 tvOS 的 `Clash.xcframework`。

使用官方应用请点击顶部的 App Store 下载链接。本仓库面向构建或集成内核的开发者。

## 上游历史与修改说明

Clash 是基于 [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo) 的独立衍生项目，上游基线为 [v1.19.32](https://github.com/MetaCubeX/mihomo/tree/v1.19.32)，提交为 `88dcbf7f1614a67c3b36b848ee3592dfa92ada36`。本项目与 MetaCubeX 无隶属关系。上游要求无隶属关系的下游项目不要在项目名称中使用“mihomo”。

仓库保留 mihomo 的原始提交及贡献者署名。首次源码发布将累计的 Clash 适配整理为一笔提交，衔接已有 README 历史与官方上游基线；这笔提交不重建适配工作的研发历史。后续修改按独立逻辑变更追加，上游稳定版本升级通过保留官方提交的合并接入。比较上游基线与具体 Clash 提交，可查看 Apple 绑定、SDK 构建工具及内核修改的完整差异。

上游 GPL-3.0 许可证保留在 [LICENSE](LICENSE) 中。署名与依赖许可证见 [NOTICE](NOTICE) 和 [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md)。

## 项目仓库

| 仓库 | 内容 |
| --- | --- |
| [Clash](https://github.com/ProjectClash/Clash) | 代理内核、Go 绑定与 Apple SDK 构建工具 |
| [Clash-Adapter](https://github.com/ProjectClash/Clash-Adapter) | Swift 数据包桥接与扩展生命周期组件 |
| [Clash-Client](https://github.com/ProjectClash/Clash-Client) | iOS、iPadOS、macOS 和 tvOS 原生应用及扩展 |

上游基线版本表示代理引擎版本，与 App Store 应用版本、SDK 发布标签分别管理。`main` 上未打发布标签的源码按预发布版本管理；集成时请固定具体提交。已发布的 SDK 版本及下载见[发行版页面](https://github.com/ProjectClash/Clash/releases)。

SDK 下载包包含五个 Apple 平台切片、许可证声明和源码清单。每次发布另附独立的许可证压缩包、macOS 所用 EasyTier 内嵌内核的对应源码包，以及用于核对下载文件的 `SHA256SUMS`。

## 仓库内容

- 基于 mihomo 的代理引擎，包括协议实现、DNS、路由规则、代理组和资源提供者。
- `bind/clash`：通过 gomobile 暴露给 Apple 应用的接口。
- `cmd/build_libbox`：SDK 生成与平台打包工具。
- [`docs/config.yaml`](docs/config.yaml)：随源码提供的配置参考。

应用负责提供配置、存储、Network Extension 接入和签名。不同平台的能力有所区别；配置能被解析，不代表所有协议和规则都已在每个平台完成端到端验证。

Apple SDK 的 iOS 和 tvOS 切片使用 `no_easytier`，不包含 EasyTier；macOS 切片未应用这一排除。平台权限、TUN 栈及出站实现仍会影响实际能力。

## 构建 Apple SDK

需要 macOS、完整的 Xcode，以及 iOS、macOS、tvOS SDK。绑定模块在 [`bind/clash/go.mod`](bind/clash/go.mod) 中声明 Go 1.26.0，并选择 Go 1.26.9 工具链；请允许 Go 获取该工具链，或自行安装。

完整克隆仓库及标签，然后安装固定版本的 gomobile 工具：

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

SDK 是静态框架，直接链接时将嵌入选项设为 **Do Not Embed**，并链接 `libresolv`。应用和扩展可通过共享的动态框架封装它，避免重复打包内核；Client 的 iOS 和 macOS 工程已采用这种结构。具体接口以所固定提交生成的头文件为准。应用源码正在 [Clash-Client](https://github.com/ProjectClash/Clash-Client) 整理发布。

## 开发与反馈

根目录 Go 模块可使用以下命令构建和测试：

```sh
go build ./...
go test ./...
```

Apple 绑定在 `bind/clash` 下有独立模块和测试。SDK 构建成功不代表签名真机上的运行行为已经验证。

内核问题请提交到本仓库的 [Issues](https://github.com/ProjectClash/Clash/issues)，附上源码提交、平台、复现步骤、预期行为与实际结果。配置示例应尽量精简，并移除密钥等敏感内容。应用界面或安装问题请提交到 [Clash-Client Issues](https://github.com/ProjectClash/Clash-Client/issues)。

安全问题请遵循 [SECURITY.md](SECURITY.md) 的报告方式。

## 许可证与致谢

Clash 基于 [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo) 及其贡献者的工作。Clash 是独立项目，与 MetaCubeX 没有隶属或背书关系。

项目采用 [GPL-3.0](LICENSE) 许可证。署名与依赖许可证见 [NOTICE](NOTICE) 和 [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md)。
