# iOS IPA playbook

An IPA is a ZIP with `Payload/Name.app/` holding the main Mach-O executable, `Info.plist`,
frameworks, plug ins and the embedded provisioning profile.

## Recognise
- `analyze_file` reports `ipa`. App Store downloads are encrypted (FairPlay); RevLens reports `cryptid` so you know whether code is readable.

## First pass
1. `mobile_ipa_info` for bundle id, versions, minimum OS, URL schemes, ATS settings, entitlements and the provisioning profile.
2. `mobile_app_framework` to spot Flutter, React Native, Unity, Xamarin or Cordova.
3. `mobile_ipa_graph` for how the app, its frameworks and extensions link together.
4. `desktop_plist_parse` for any other plist in the bundle, binary or XML.

## Code
1. Continue with the Mach-O playbook on the main executable and each framework.
2. If `cryptid` is 1 the code section is encrypted. Say so plainly and analyze only metadata, strings outside the encrypted range and unencrypted frameworks.
3. React Native apps keep JavaScript in `main.jsbundle`; use the JS bundle playbook. Hermes bytecode is reported by `x_v8_inspect`.

## Verify
- Entitlements and ATS exceptions are quoted from the plist path; cite the path inside the IPA.
