<div align="center">

# RevLens

**যেকোনো ফাইলের ভেতরে কী আছে দেখুন: ব্রাউজারে, টার্মিনালে, অথবা আপনার AI এজেন্টে।**

[English](../../README.md) · বাংলা · [हिन्दी](README.hi.md) · [中文](README.zh.md) · [日本語](README.ja.md) · [Español](README.es.md)

</div>

## RevLens কী

আপনার হাতে একটি ফাইল আর একটি প্রশ্ন। এই বাইনারি কি প্যাক করা? `main` ফাংশন কী করে? এই APK কোন কোন অনুমতি চায়, আর কে এটি সাইন করেছে? এই Electron অ্যাপ, PyInstaller বিল্ড বা .NET অ্যাসেম্বলির ভেতরে কী আছে? এই প্যাকেট ক্যাপচার কোন কোন হোস্টের সাথে কথা বলে?

RevLens প্রমাণসহ উত্তর দেয়: বাইট অফসেট, ভার্চুয়াল অ্যাড্রেস, সেকশনের নাম আর আর্কাইভের পথ, যা আপনি নিজে যাচাই করতে পারেন। পুরো ইঞ্জিন TypeScript আর দুটি WebAssembly ডিকোডারে লেখা। কোনো নেটিভ ইনস্টল লাগে না, তাই একই কোড তিন জায়গায় চলে:

- **ব্রাউজারে**, একটি Web Worker-এর ভেতরে। আপনার ফাইল আপনার কম্পিউটার ছেড়ে কোথাও যায় না।
- **টার্মিনালে**, `npx revlens` হিসেবে, JSON, Markdown, HTML, SARIF আর CycloneDX আউটপুটসহ।
- **আপনার এজেন্টে**, একটি MCP সার্ভার হিসেবে (117 MCP tools, 83 CLI commands), সাথে Claude Code আর Codex-এর জন্য তৈরি স্কিল ও প্লাগইন।

আপনার কম্পিউটারে Ghidra, radare2, jadx, ILSpy, Frida বা gdb থাকলে RevLens সেগুলোও চালাতে পারে। `revlens doctor` বলে দেয় কী নেই আর কীভাবে ইনস্টল করবেন।

RevLens তৈরি হয়েছে morluto-র [REA, Reverse Engineer Anything](https://github.com/morluto/rea) থেকে অনুপ্রাণিত হয়ে। এটি শূন্য থেকে লেখা, এবং এটি REA-র কোনো অফিশিয়াল প্রজেক্ট নয়।

## কী কী পড়তে পারে

| ক্ষেত্র | ফরম্যাট | কী পাবেন |
| --- | --- | --- |
| যেকোনো ফাইলের প্রাথমিক বিশ্লেষণ | ELF, PE, Mach-O, WASM, ZIP, APK, npm tgz, ASAR, JS বান্ডল | ফরম্যাট, হ্যাশ, সেকশন ও এনট্রপি, ইমপোর্ট, হার্ডেনিং, প্যাকার, স্ট্রিং, সিক্রেট, এন্ডপয়েন্ট, ATT&CK ক্ষমতা, yara-lite রুল, SBOM, দাবি যাচাই |
| নেটিভ কোড | x86, x86-64, AArch64, ARM, Thumb | ফাংশন, কন্ট্রোল ফ্লো গ্রাফ, ক্রস রেফারেন্স, কল গ্রাফ, সহজপাঠ্য সিউডো কোড |
| Android, Java, iOS | APK, DEX, JAR, class, IPA | ম্যানিফেস্ট, সিগনেচার, baksmali-র মতো smali, javap আউটপুট, IPA plist ও entitlements |
| ম্যানেজড রানটাইম | .NET, Python pyc, PyInstaller, Lua, BEAM, EVM | মেটাডেটা ও CIL, dis আউটপুট, আর্কাইভ এক্সট্র্যাকশন, EVM সিলেক্টর |
| JavaScript ও Electron | JS, বান্ডল, সোর্স ম্যাপ, ASAR | ডিঅবফাসকেশন, বান্ডল ভাগ করা, এন্ডপয়েন্ট, Electron নিরাপত্তা অডিট |
| নেটওয়ার্ক ও ডেটা | PCAP, pcapng, HAR, SQLite | ফ্লো, DNS, HTTP, TLS SNI ও JA3, শুধু পড়ার SELECT |
| এক্সট্রাস | ফার্মওয়্যার, GPU কোড, মডেল ফাইল, LNK, ক্র্যাশ রিপোর্ট | ডিম্যাঙ্গলিং, checksec, গভীর PE ও Authenticode, প্রমাণের লেজার |
| বাইরের টুল | Ghidra, radare2, jadx, ILSpy, Frida, gdb এবং আরও | ডিকম্পাইল করা C, Java ও C#, অনুমতি নিয়ে ডায়নামিক রান |

## দ্রুত শুরু

```bash
npx revlens setup claude-code --write   # অথবা codex, cursor, vscode, windsurf
npx revlens doctor                      # কোন বাইরের টুল আছে দেখুন
```

`--write` না দিলে setup শুধু পরিবর্তনটি দেখায়, কিছু লেখে না। দিলে আগে পুরনো কনফিগের ব্যাকআপ নেয়।

টার্মিনালে:

```bash
npx revlens analyze ./app.elf
npx revlens decompile ./app.elf main
npx revlens apk ./app.apk
npx revlens verify ./app.elf string=api.example.com
```

ব্রাউজারে: [aniruddhaadak80.github.io/re](https://aniruddhaadak80.github.io/re/) খুলে একটি ফাইল দিন, অথবা [টুলস](https://aniruddhaadak80.github.io/re/labs) পাতায় "Try a sample" চাপুন। কিছুই আপলোড হয় না।

## এজেন্টরা কীভাবে ব্যবহার করে

MCP সার্ভার এজেন্টকে বলে আগে `analyze_file` চালাতে, তারপর ফরম্যাট অনুযায়ী সঠিক টুলে যেতে, আর কোনো তথ্য বলার আগে `verify_claim` দিয়ে বাইটের সাথে মিলিয়ে নিতে। পুরো পদ্ধতি লেখা আছে [revlens-reverse-engineer স্কিলে](../../.agents/skills/revlens-reverse-engineer/SKILL.md)।

## আরও পড়ুন

[ডকস](https://aniruddhaadak80.github.io/re/docs) · [উদাহরণসহ ওয়াকথ্রু](../showcases/README.md) · [তুলনা](../comparison.md) · [লাইসেন্স: MIT](../../LICENSE)

লেখক: অনিরুদ্ধ আদক ([GitHub](https://github.com/aniruddhaadak80))
