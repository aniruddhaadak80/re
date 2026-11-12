# Android APK playbook

An APK is a ZIP holding `AndroidManifest.xml` (binary XML), one or more `classes*.dex`, resources,
native libraries under `lib/<abi>/` and a signature.

## Recognise
- `analyze_file` reports `apk`. A bare `.dex` reports `dex`, and an AAB keeps its manifest under `base/manifest/`.

## First pass
1. `mobile_apk_report` for one summary: package, versions, SDK levels, permissions, components, signing, frameworks and native libraries.
2. `mobile_manifest` for exported activities, services, receivers and providers. Exported components without a permission are the first attack surface.
3. `mobile_signing` for the v1, v2, v3 and v4 signature schemes and certificate digests.
4. `mobile_app_framework` to tell native Java or Kotlin from Flutter, React Native, Xamarin, Unity or Cordova.

## Code
1. `mobile_dex_classes` with a package filter, then `mobile_dex_method` for the smali and a Java like view.
2. `mobile_dex_search` for strings such as URLs, keys and SQL, then `mobile_dex_xrefs` for their users.
3. `mobile_jni_map` links `native` Java methods to the exports in `lib/<abi>/*.so`; continue in the ELF playbook for those libraries.
4. Unity apps: `mobile_il2cpp_types` reads `global-metadata.dat`.

## Bridges that help
- jadx (`bridge_jadx_decompile`, `bridge_jadx_search`) for full Java source.
- apktool (`bridge_apktool_decode`) for resources and smali you can rebuild.
- adb (`bridge_adb_*`) and Frida (`bridge_frida_session_*`) for a device, only with `allowExecution: true` and a test device.

## Verify
- Cite the DEX file, class, method and bytecode offset, or the manifest element, for each claim.
