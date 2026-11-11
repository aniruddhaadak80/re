# @revlens/mobile

Android, Java and iOS app reverse engineering for RevLens, written in plain TypeScript. No Java,
no Android SDK, no native code. It runs in Node and in a browser Web Worker.

What it reads:

- **Android binary XML (AXML)**: `AndroidManifest.xml`, `res/xml/*.xml` and the `resources.arsc`
  resource table. Gives package, version, min and target SDK, permissions with protection level and
  a short risk note, activities, services, receivers and providers with their effective exported
  state and intent filters, deep links, network security config, and the `debuggable`,
  `allowBackup`, `usesCleartextTraffic` and `testOnly` flags. Labels and `@xml/` references are
  resolved through `resources.arsc`.
- **APK signatures**: v1 (`META-INF/*.SF` and the PKCS#7 `*.RSA|DSA|EC` certificates with subject,
  issuer, serial, validity and SHA-256), the APK Signing Block ids, v2, v3 and v3.1 signers with
  certificate digests, SDK ranges and algorithms. It reports what is present. It does not verify
  digests or signatures.
- **DEX** (versions 035 to 041, multidex, AAB `base/dex/`): strings, types, protos, fields,
  methods, classes, encoded values, debug line tables, call sites and method handles, and a Dalvik
  disassembler whose smali output matches baksmali line for line. On top of that: cross references
  (calls, field reads and writes, string and type use), name and string search, library detection
  by package prefix, obfuscation hints, sensitive API use (reflection, dynamic code loading, native
  loading, exec, WebView bridges, SMS, device ids and more), hardcoded URLs and keys, and JNI names
  for every `native` method.
- **Java class files** and JAR members, with a JVM disassembler whose output matches `javap -c -p`.
- **Native libraries** in `lib/<abi>/*.so`: per ABI, soname, needed libraries, exports,
  `JNI_OnLoad`, `ANativeActivity_onCreate` and `Java_*` symbols, build id. DEX native methods with
  no static export are counted, a hint that they are bound with `RegisterNatives`.
- **iOS IPA**: `Info.plist` (binary and XML), URL schemes, App Transport Security, privacy usage
  strings, background modes, embedded frameworks and dylibs, app extensions, the provisioning
  profile, and from the main executable's code signature: identifier, team id, flags and
  entitlements. Also the encryption state per slice. The archive path of the main executable is
  returned so `@revlens/core` can do the full Mach-O analysis (the IPA analyzer hands it over as a
  child report).
- **Framework detection** for APK and IPA: Flutter (with the Dart snapshot hash from `libapp.so`),
  React Native (Hermes bytecode or plain JS bundle), Xamarin and .NET MAUI, Unity IL2CPP and Mono,
  Cordova, Capacitor, Godot, Qt, Cocos2d-x, Unreal, libGDX, NativeActivity and Kotlin.
- **Unity IL2CPP `global-metadata.dat`** (versions 24 to 31): header sections, images, type names,
  method names with their declaring type, and string literals. Struct strides are inferred and
  checked against the data instead of being hardcoded per Unity release.

## API

```ts
import { analyzeApk, apkSigning, openDex, renderClass, parseClass, javap, analyzeIpa, TOOLS, CLI_COMMANDS, ANALYZERS } from '@revlens/mobile';
// Node only: registers a file reader so tools accept { path }
import { runCli } from '@revlens/mobile/node';

const report = await analyzeApk(apkBytes);            // manifest, signing, dex, native libs, frameworks, findings
const [dex] = openDex(dexBytes);
const smali = renderClass(dex, dex.classByName('com.example.Main')!);
const text = javap(parseClass(classBytes));
```

Main exports: `analyzeApk`, `readManifest`, `parseManifest`, `parseAxml`, `axmlToXml`,
`parseResourceTable`, `apkSigning`, `loadDexes`, `openDex`, `DexFile`, `decodeCode`, `renderClass`,
`renderMethod`, `xrefIndex`, `searchDex`, `findMethod`, `detectLibraries`, `obfuscationHints`,
`sensitiveApis`, `scanStrings`, `nativeMethods`, `jniNames`, `parseClass`, `javap`, `decodeJvm`,
`parseElfDynamic`, `parsePlist`, `parseMachoSlices`, `analyzeIpa`, `detectFrameworks`,
`dartSnapshotInfo`, `reactNativeBundleInfo`, `parseIl2cppMetadata`.

### Analyzers (for `@revlens/core`)

Rich output goes to `report.meta.mobile.<apk|dex|javaClass|ipa|il2cpp>`.

| id | applies to | adds |
| --- | --- | --- |
| `mobile-apk` | APK, or a ZIP with `AndroidManifest.xml` | manifest, signing, dex, native, framework summary; findings (debuggable, backup, cleartext, network security config, exported components, unverified app links, Janus, debug certificate, packers, sensitive APIs, hardcoded keys); libraries as components; API use as capabilities |
| `mobile-dex` | DEX | dex summary, libraries, obfuscation, API use, URLs, keys |
| `mobile-class` | Java class | declaration, methods |
| `mobile-ipa` | ZIP with `Payload/*.app/Info.plist` | IPA summary; ATS, `get-task-allow`, encryption and URL scheme findings; main executable as a child report |
| `mobile-il2cpp` | `global-metadata.dat` | version, images, counts, sample type names |

### Tools

Every tool takes `path` (Node, through `@revlens/mobile/node`) or `base64`, returns JSON with
archive paths, offsets or DEX names as evidence, and pages long lists with `offset` and `limit`
(max 1000).

| name | what it does |
| --- | --- |
| `mobile_manifest` | decoded manifest summary, optional XML text |
| `mobile_signing` | v1, v2, v3, v3.1 signatures and certificates |
| `mobile_dex_classes` | DEX files and classes, libraries, obfuscation hints |
| `mobile_dex_method` | smali for one method or a whole class |
| `mobile_dex_search` | search class, method, field names and strings |
| `mobile_dex_xrefs` | who calls, reads, writes or uses something; or what one method references |
| `mobile_java_class` | javap style disassembly of a class or a class inside a JAR |
| `mobile_ipa_info` | IPA summary, or entitlements of a Mach-O, or a plist |
| `mobile_app_framework` | Flutter, React Native, Xamarin, Unity and other frameworks |
| `mobile_il2cpp_types` | IL2CPP images, types, methods or string literals |
| `mobile_native_libs` | native libraries per ABI and JNI entry points |
| `mobile_apk_report` | one-shot APK triage with findings |

### CLI commands

Each prints text by default and JSON with `--json`.

`apk`, `manifest [--xml]`, `apksig`, `dex [--filter]`, `smali --class C [--method M] [--lines]`,
`dex-search --query Q [--kinds]`, `xrefs --target T [--kind] [--direction from --class C]`,
`javap [--class] [--method]`, `ipa [--plist]`, `app-framework`,
`il2cpp [--what types|methods|literals|images|summary] [--filter]`, `native-libs`.

## Verified against

- **androguard 4.1.4** on four F-Droid APKs: package, version code and name, SDK levels, label,
  main activity, permissions, every activity, service, receiver and provider, v1/v2/v3 presence,
  certificate subject, serial and SHA-256, v2 and v3 signer digests, DEX class, method id, field id
  and string counts.
- **baksmali 2.5.2**: every method of three real F-Droid `classes.dex` files (more than 1600 methods,
  dex 035 and 039) plus D8 builds of test code renders to the same instructions, labels, switch and
  array payloads and try/catch directives.
- **javap (JDK 17)**: identical `javap -c -p` output for all classes of Apache Commons CLI 1.6.0 and
  for a test class with switches, exceptions, lambdas and natives.
- **readelf and nm** for native library needed lists and exports.
- **Python plistlib** for binary and XML plists, **rcodesign 0.29.0** for the code signature
  identifier, digest type, flags and offset.
- `strings` for the Flutter Dart snapshot hash; real Daggerfall Unity metadata (v29: 59 images,
  12280 types) for IL2CPP.

Fixture sources and licenses are in `samples/mobile/SOURCES.md`. Run
`node packages/mobile/scripts/fetch-fixtures.mjs` to download the larger optional fixtures.

## Limits

- Signatures are inspected, not verified.
- AAB manifests (aapt2 protobuf format) are not decoded yet; DEX and native libs in AABs are.
- DEX 041 container files are split on each header's file size; offsets are read as absolute.
- Odex and quickened opcodes are shown as unknown. `invoke-custom` and `invoke-polymorphic`
  decode but are not covered by a real-file test.
- IL2CPP: versions 24 to 31 only. Encrypted or renamed metadata is reported, not decrypted. Method
  signatures and field names are not decoded.
- Hermes bytecode is detected, not disassembled. Dart AOT code is not decompiled.
- IPA: FairPlay encrypted executables are flagged; their code cannot be read.
- Limits on input size, table counts, nesting depth, instruction counts and decompressed size
  protect against hostile files (see `ZIP_LIMITS`, `DEX_LIMITS`, `AXML_LIMITS`, `PLIST_LIMITS`).

## Tests

```
npx tsc -p packages/core          # @revlens/core types are imported from its dist
node --test --import tsx packages/mobile/test/*.test.ts
npx tsc -p packages/mobile --noEmit
```
