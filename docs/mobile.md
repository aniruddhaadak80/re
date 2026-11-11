---
title: Android, Java and iOS
description: Read APK manifests and signatures, DEX as smali, Java class files as javap output, IPA plists and entitlements, app frameworks and Unity IL2CPP metadata in plain TypeScript.
order: 21
---

# Android, Java and iOS

`@revlens/mobile` reads mobile app packages without Java, the Android SDK or Xcode. It runs in Node and in the browser. Try it on the [mobile page](https://aniruddhaadak80.github.io/re/labs/mobile).

## What it reads

| Input | What you get |
| --- | --- |
| APK | decoded manifest (package, versions, SDK levels, permissions with risk notes, components with their real exported state, deep links, network security config, risky flags), signatures (v1, v2, v3, v3.1 with certificates), DEX summary, native libraries per ABI, frameworks, findings |
| DEX (035 to 041, multidex) | classes, methods, fields, strings, smali that matches baksmali line for line, cross references, search, library and obfuscation hints, sensitive API use, JNI names |
| JAR and .class | `javap -c -p` style output that matches the JDK tool |
| IPA | Info.plist, URL schemes, App Transport Security, privacy strings, frameworks, extensions, provisioning profile, code signature identifier, team id and entitlements, encryption state |
| Unity `global-metadata.dat` | IL2CPP images, types, methods and string literals (versions 24 to 31) |

Frameworks detected in APK and IPA: Flutter (with the Dart snapshot hash), React Native (Hermes or plain JS), Xamarin and .NET MAUI, Unity IL2CPP and Mono, Cordova, Capacitor, Godot, Qt, Cocos2d-x, Unreal, libGDX and Kotlin.

## CLI

```
revlens apk app.apk
revlens manifest app.apk --xml
revlens apksig app.apk
revlens dex app.apk --filter com.example
revlens smali app.apk --class com.example.Main --method onCreate
revlens dex-search app.apk --query https://
revlens javap Hello.class
revlens ipa App.ipa
revlens native-libs app.apk
```

## MCP tools

`mobile_apk_report`, `mobile_manifest`, `mobile_signing`, `mobile_dex_classes`, `mobile_dex_method`, `mobile_dex_search`, `mobile_dex_xrefs`, `mobile_java_class`, `mobile_ipa_info`, `mobile_app_framework`, `mobile_il2cpp_types`, `mobile_native_libs`. Every list pages with `offset` and `limit`.

For Java source instead of smali, install jadx and use `bridge_jadx_decompile` and `bridge_jadx_search` (see [bridges](bridges.md)). To pull an APK from a phone, `bridge_adb_pull_apk`.

## Limits

- Signatures are inspected, not verified.
- AAB manifests (protobuf) are not decoded yet. DEX and native libraries inside AAB files are.
- Hermes bytecode is detected, not disassembled. Dart AOT code is not decompiled.
- FairPlay encrypted iOS executables are flagged. Their code cannot be read.

## How it was checked

androguard on four F-Droid APKs, baksmali on more than 1600 methods, javap on all of Apache Commons CLI, readelf and nm for native libraries, plistlib and rcodesign for iOS. See the [package README](https://github.com/aniruddhaadak80/re/tree/main/packages/mobile).
