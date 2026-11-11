# Mobile test fixtures: sources and licenses

All files here are small, real artifacts used by `packages/mobile/test`. Larger real apps are
fetched on demand by `packages/mobile/scripts/fetch-fixtures.mjs` into `samples/.cache/mobile/`
(not committed); the tests that need them skip when they are missing.

## apk/ (F-Droid builds, signed by F-Droid or the developer, unmodified)

| File | App | License | Source |
| --- | --- | --- | --- |
| `com.angrydoughnuts.android.alarmclock_27.apk` | Alarm Klock 2.13 | Apache-2.0 | https://f-droid.org/repo/com.angrydoughnuts.android.alarmclock_27.apk |
| `de.markusfisch.android.screentime_16.apk` | Screen Time 1.4.0 (Kotlin, R8) | Unlicense | https://f-droid.org/repo/de.markusfisch.android.screentime_16.apk |
| `omegacentauri.mobi.simplestopwatch_31.apk` | Giant Stopwatch 1.31 | MIT | https://f-droid.org/repo/omegacentauri.mobi.simplestopwatch_31.apk |
| `org.rayg.streaktracker_12.apk` | Streak 1.4.0 (NDK NativeActivity, 4 ABIs, no DEX) | MIT | https://f-droid.org/repo/org.rayg.streaktracker_12.apk |

SHA-256: bf15ea9d..09cb, 02df7818..19a2, a3634375..8e1f, 0f073c6c..4afd (see `sha256sum`).

## java/

| File | What | License |
| --- | --- | --- |
| `src/Hello.java`, `Hello.class`, `hello.jar` | Written for RevLens, compiled with Eclipse Temurin javac 17.0.21 `--release 8` | MIT (this repo) |
| `hello-035.dex`, `hello-039.dex` | `hello.jar` converted with D8 from R8 8.5.35 (`--release --min-api 21` and `--min-api 28`) | MIT (this repo) |
| `multidex.zip` | `classes.dex` = hello-035.dex, `classes2.dex` = `src/Second.java` through javac + D8 (with `src/DexClassLoader-stub.java` as the library stub) | MIT (this repo) |
| `commons-cli-1.6.0.jar` | Apache Commons CLI 1.6.0 from Maven Central, https://repo1.maven.org/maven2/commons-cli/commons-cli/1.6.0/commons-cli-1.6.0.jar | Apache-2.0 |

## ipa/Wikipedia-fixture.ipa

A minimal but structurally real IPA. A real App Store IPA cannot be redistributed, so this one is
assembled from real, MIT-licensed plists of the Wikipedia iOS app
(https://github.com/wikimedia/wikipedia-ios, MIT):

- `Payload/Wikipedia.app/Info.plist`: `Wikipedia/Local-Info.plist` with Xcode build variables
  substituted (bundle id `org.wikimedia.wikipedia`, executable `Wikipedia`), plus `MinimumOSVersion`,
  `CFBundleSupportedPlatforms` and `UIDeviceFamily` that Xcode adds, written as a binary plist by
  Python `plistlib` (the same `bplist00` format Xcode writes).
- `PlugIns/Widgets.appex/Info.plist`: `Widgets/Info.plist`, variables substituted, kept as XML.
- `Frameworks/WMF.framework/Info.plist`: `WMF Framework/Info.plist`, variables substituted.
- `Wikipedia` (main executable): a tiny arm64 Mach-O from `packages/mobile/scripts/make-ipa-macho.py`,
  ad-hoc signed with rcodesign 0.29.0 (https://github.com/indygreg/apple-platform-rs, MPL-2.0, used
  only as a tool) using `Wikipedia/Wikipedia.entitlements` with `$(SIGNING_DISAMBIGUATOR)` removed and
  `get-task-allow` plus `application-identifier` added the way a development build has them:
  `rcodesign sign --binary-identifier org.wikimedia.wikipedia --entitlements-xml-file ent.plist in out`.
- `Frameworks/WMF.framework/WMF`: the same Mach-O, unsigned.

## expected/ and reference/

Outputs of real reference tools, regenerated with `packages/mobile/scripts/gen-expected.py` and
`gen-androguard.py`:

- `expected/*.baksmali.json.gz`: baksmali 2.5.2 (BSD-3-Clause,
  https://bitbucket.org/JesusFreke/smali/downloads/baksmali-2.5.2.jar) method bodies, normalized
  (no `.line`, `.local`, `.param`, annotations or `#` comments).
- `expected/Hello.javap.txt`, `expected/commons-cli-1.6.0.javap.txt.gz`: `javap -c -p` from JDK 17.0.21.
- `reference/androguard.json`: androguard 4.1.4 (Apache-2.0) package, versions, SDK levels, label,
  permissions, components, signature schemes, certificates and DEX table counts.
- `reference/wikipedia-ipa-plists.json`: Python plistlib decoding of the IPA plists.
- `reference/wikipedia-rcodesign.yaml`: `rcodesign print-signature-info` of the signed executable.

## Fetched on demand (samples/.cache/mobile/, not committed)

- Daggerfall Unity Android port v1.1.1.2, MIT, https://github.com/Vwing/daggerfall-unity-android:
  central directory listings of the IL2CPP 64-bit and Mono 32-bit APKs, their manifests, and
  `global-metadata.dat` (IL2CPP metadata v29), pulled with HTTP range requests.
- LocalSend 1.18.2 (F-Droid build 643), Apache-2.0, https://github.com/localsend/localsend:
  listing, manifest, `resources.arsc` and the first 1 MB of `lib/arm64-v8a/libapp.so` (Flutter).
