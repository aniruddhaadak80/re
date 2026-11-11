<div align="center">

# RevLens

**どんなファイルでも中身を見る。ブラウザでも、ターミナルでも、AI エージェントの中でも。**

[English](../../README.md) · [বাংলা](README.bn.md) · [हिन्दी](README.hi.md) · [中文](README.zh.md) · 日本語 · [Español](README.es.md)

</div>

## RevLens とは

手元にファイルがひとつと、疑問がひとつある。このバイナリはパックされているのか。`main` 関数は何をしているのか。この APK はどんな権限を要求していて、誰が署名したのか。この Electron アプリや PyInstaller のビルド、.NET アセンブリの中には何が入っているのか。このパケットキャプチャはどのホストと通信しているのか。

RevLens は、自分で確かめられる根拠を添えて答えます。バイトオフセット、仮想アドレス、セクション名、アーカイブ内のパスです。エンジン全体は TypeScript と 2 つの WebAssembly デコーダで書かれています。ネイティブのインストールが要らないので、同じコードが 3 か所で動きます。

- **ブラウザ**では Web Worker の中で動きます。ファイルがあなたのマシンの外に出ることはありません。
- **ターミナル**では `npx revlens` として動き、JSON、Markdown、HTML、SARIF、CycloneDX で出力できます。
- **エージェント**では MCP サーバーとして動きます（MCP ツール 117 個、CLI コマンド 83 個）。Claude Code と Codex 向けのスキルとプラグインも用意しています。

Ghidra、radare2、jadx、ILSpy、Frida、gdb が入っていれば、RevLens はそれらも呼び出します。足りないものとそのインストール方法は `revlens doctor` が教えてくれます。

RevLens は morluto の [REA, Reverse Engineer Anything](https://github.com/morluto/rea) に影響を受けています。ゼロから書いたもので、REA の公式プロジェクトではありません。

## 読めるもの

| 分野 | 形式 | 得られるもの |
| --- | --- | --- |
| どんなファイルでも最初の調査 | ELF、PE、Mach-O、WASM、ZIP、APK、npm tgz、ASAR、JS バンドル | 形式、ハッシュ、セクションとエントロピー、インポート、ハードニング、パッカー、文字列、シークレット、エンドポイント、ATT&CK の機能、yara-lite ルール、SBOM、主張の検証 |
| ネイティブコード | x86、x86-64、AArch64、ARM、Thumb | 関数、制御フローグラフ、相互参照、コールグラフ、読みやすい疑似コード |
| Android、Java、iOS | APK、DEX、JAR、class、IPA | マニフェスト、署名、baksmali 風の smali、javap 風の出力、IPA の plist と entitlements |
| マネージドランタイム | .NET、Python pyc、PyInstaller、Lua、BEAM、EVM | メタデータと CIL、dis の出力、アーカイブの展開、EVM セレクタ |
| JavaScript と Electron | JS、バンドル、ソースマップ、ASAR | 難読化の解除、バンドルのモジュール分割、エンドポイント、Electron のセキュリティ監査 |
| ネットワークとデータ | PCAP、pcapng、HAR、SQLite | フロー、DNS、HTTP、TLS SNI と JA3、読み取り専用の SELECT |
| その他 | ファームウェア、GPU コード、モデルファイル、LNK、クラッシュレポート | デマングル、checksec、PE と Authenticode の詳しい解析、証拠の台帳 |
| 外部ツール | Ghidra、radare2、jadx、ILSpy、Frida、gdb など | 逆コンパイルした C、Java、C#、許可を得たうえでの動的実行 |

## すぐに始める

```bash
npx revlens setup claude-code --write   # codex、cursor、vscode、windsurf も可
npx revlens doctor                      # 使える外部ツールを確認
```

`--write` を付けないと、setup は変更内容を表示するだけで何も書き込みません。`--write` を付けると、先に既存の設定をバックアップします。

ターミナルでは:

```bash
npx revlens analyze ./app.elf
npx revlens decompile ./app.elf main
npx revlens apk ./app.apk
npx revlens verify ./app.elf string=api.example.com
```

ブラウザでは: [aniruddhaadak80.github.io/re](https://aniruddhaadak80.github.io/re/) を開いてファイルをドロップするか、[ツール](https://aniruddhaadak80.github.io/re/labs) ページで "Try a sample" を押してください。何もアップロードされません。

## エージェントでの使われ方

MCP サーバーはエージェントに、まず `analyze_file` を実行し、形式に合ったツールに進み、何かを言い切る前に `verify_claim` でバイトと照合するよう促します。手順の全体は [revlens-reverse-engineer スキル](../../.agents/skills/revlens-reverse-engineer/SKILL.md) にまとめてあります。

## もっと読む

[ドキュメント](https://aniruddhaadak80.github.io/re/docs) · [実際の出力つきのウォークスルー](../showcases/README.md) · [比較](../comparison.md) · [ライセンス: MIT](../../LICENSE)

作者: Aniruddha Adak（[GitHub](https://github.com/aniruddhaadak80)）
