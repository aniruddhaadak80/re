<div align="center">

# RevLens

**看清任何文件的内部：在浏览器里，在终端里，或者在你的 AI 智能体里。**

[English](../../README.md) · [বাংলা](README.bn.md) · [हिन्दी](README.hi.md) · 中文 · [日本語](README.ja.md) · [Español](README.es.md)

</div>

## RevLens 是什么

你手里有一个文件，还有一个问题。这个二进制文件加壳了吗？`main` 函数做了什么？这个 APK 申请了哪些权限，是谁签的名？这个 Electron 应用、PyInstaller 打包程序或 .NET 程序集里面装了什么？这份抓包数据和哪些主机通信？

RevLens 会给出你可以自己核对的证据来回答：字节偏移、虚拟地址、节名和归档内路径。整个引擎用 TypeScript 和两个 WebAssembly 解码器写成，不需要安装任何原生组件，所以同一套代码可以在三个地方运行：

- **浏览器里**，在 Web Worker 中运行。你的文件不会离开你的电脑。
- **终端里**，通过 `npx revlens` 使用，可以输出 JSON、Markdown、HTML、SARIF 和 CycloneDX。
- **智能体里**，作为 MCP 服务器运行（203 个 MCP 工具，117 个 CLI 命令），并附带给 Claude Code 和 Codex 用的现成技能和插件。

如果你装了 Ghidra、radare2、jadx、ILSpy、Frida 或 gdb，RevLens 也能调用它们。`revlens doctor` 会告诉你缺了什么，以及怎么安装。

RevLens 的灵感来自 morluto 的 [REA, Reverse Engineer Anything](https://github.com/morluto/rea)。它是从零开始写的，不是 REA 的官方项目。

## 它能读什么

| 领域 | 格式 | 你能得到什么 |
| --- | --- | --- |
| 任意文件的初步检查 | ELF、PE、Mach-O、WASM、ZIP、APK、npm tgz、ASAR、JS 打包文件 | 格式、哈希、节和熵、导入表、加固选项、加壳器、字符串、密钥、接口地址、ATT&CK 能力、yara-lite 规则、SBOM、结论核验 |
| 原生代码 | x86、x86-64、AArch64、ARM、Thumb | 函数、控制流图、交叉引用、调用图、易读的伪代码、值流追踪、跳转表和虚表解析、跨版本函数匹配 |
| Android、Java、iOS | APK、DEX、JAR、class、IPA | 清单文件、签名、类似 baksmali 的 smali、javap 风格输出、IPA 的 plist 和 entitlements、应用组件图、JNI 映射、成员对比 |
| 托管运行时 | .NET、Python pyc、PyInstaller、Lua、BEAM、EVM | 元数据和 CIL、dis 输出、归档提取、EVM 函数选择器 |
| JavaScript 和 Electron | JS、打包文件、source map、ASAR、在线页面 | 反混淆、把打包文件拆成模块、接口地址、Electron 安全审计、带断言的浏览器场景脚本、两次运行的对比 |
| 网络和数据 | PCAP、pcapng、HAR、SQLite | 会话流、DNS、HTTP、TLS SNI 和 JA3、只读 SELECT |
| 扩展 | 固件、GPU 代码、模型文件、LNK、崩溃报告、注册表、Prefetch、Jump List、nib、Assets.car、wxapkg、UnityFS | C++、Rust、MSVC 和 Swift 符号还原、checksec、深入的 PE 和 Authenticode 分析、protobuf、OpenAPI 和 GraphQL 接口契约、证据账本 |
| 桌面 | 进程、已安装的应用、原生界面 | 模块、打开的文件和套接字、快照对比、Electron 应用识别、无障碍树 |
| 外部工具 | Ghidra、radare2、jadx、ILSpy、Frida、gdb 等 | 反编译出的 C、Java 和 C#，经你同意后的动态运行，长时间保持的调试会话，把函数名写回 Ghidra、IDA 和 radare2 |

## 快速开始

```bash
npx revlens setup claude-code --write   # 也可以是 codex、cursor、vscode、windsurf
npx revlens doctor                      # 查看有哪些外部工具可用
```

不加 `--write` 时，setup 只会显示要改什么，不会写入任何东西。加上 `--write` 后，它会先备份原有配置。

在终端里：

```bash
npx revlens analyze ./app.elf
npx revlens decompile ./app.elf main
npx revlens apk ./app.apk
npx revlens verify ./app.elf string=api.example.com
```

在浏览器里：打开 [aniruddhaadak80.github.io/re](https://aniruddhaadak80.github.io/re/) 把文件拖进去，或者在 [工具](https://aniruddhaadak80.github.io/re/labs) 页面点 "Try a sample"。不会上传任何东西。

## 智能体怎么用它

MCP 服务器会引导智能体先运行 `analyze_file`，再根据格式选择合适的工具，并且在下任何结论之前，先用 `verify_claim` 拿字节去核对。完整做法写在 [revlens-reverse-engineer 技能](../../.agents/skills/revlens-reverse-engineer/SKILL.md) 里。

## 延伸阅读

[文档](https://aniruddhaadak80.github.io/re/docs) · [带真实输出的演练](../showcases/README.md) · [对比](../comparison.md) · [许可证：MIT](../../LICENSE)

`@revlens/extras` 中的 Swift 符号还原代码移植自 Swift 项目（Apple Inc. 和 Swift 项目作者），使用带运行时库例外的 Apache License 2.0，详见 [NOTICE](../../NOTICE)。

作者：Aniruddha Adak（[GitHub](https://github.com/aniruddhaadak80)）
