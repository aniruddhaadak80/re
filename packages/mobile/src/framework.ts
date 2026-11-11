// Cross-platform framework detection for Android and iOS app packages, from member names
// plus a few cheap content checks (Hermes bytecode magic, Dart snapshot hash).

import { indexOfBytes, utf8 } from './bytes.js';

export interface FrameworkHit {
  id: 'flutter' | 'react-native' | 'xamarin' | 'dotnet-maui' | 'unity-il2cpp' | 'unity-mono' | 'cordova' | 'capacitor' | 'godot' | 'qt' | 'cocos2dx' | 'unreal' | 'libgdx' | 'native-activity' | 'kotlin' | 'nativescript';
  name: string;
  confidence: number;
  evidence: string[];
  details?: Record<string, unknown>;
}

interface Rule { id: FrameworkHit['id']; name: string; patterns: RegExp[]; weight?: number[] }

const RULES: Rule[] = [
  { id: 'flutter', name: 'Flutter', patterns: [/(^|\/)lib\/[^/]+\/libflutter\.so$/, /(^|\/)lib\/[^/]+\/libapp\.so$/, /^assets\/flutter_assets\//, /Frameworks\/Flutter\.framework\//, /Frameworks\/App\.framework\//, /flutter_assets\//] },
  { id: 'react-native', name: 'React Native', patterns: [/^assets\/index\.android\.bundle$/, /lib\/[^/]+\/libreactnativejni\.so$/, /lib\/[^/]+\/libhermes\.so$/, /lib\/[^/]+\/libjsc\.so$/, /\.app\/main\.jsbundle$/, /lib\/[^/]+\/libreact_nativemodule_core\.so$/] },
  { id: 'xamarin', name: 'Xamarin / .NET for Android or iOS', patterns: [/^assemblies\/.+\.dll$/, /^assemblies\/assemblies\.blob$/, /lib\/[^/]+\/libmonodroid\.so$/, /lib\/[^/]+\/libxamarin-app\.so$/, /lib\/[^/]+\/libmonosgen-2\.0\.so$/, /\.app\/Xamarin\.iOS\.dll$/, /\.app\/Microsoft\.iOS\.dll$/, /lib\/[^/]+\/libassemblies\.[^/]+\.blob\.so$/] },
  { id: 'dotnet-maui', name: '.NET MAUI', patterns: [/Microsoft\.Maui\.dll$/, /Microsoft\.Maui\.Controls\.dll$/] },
  { id: 'unity-il2cpp', name: 'Unity (IL2CPP)', patterns: [/lib\/[^/]+\/libil2cpp\.so$/, /Data\/Managed\/Metadata\/global-metadata\.dat$/, /Frameworks\/UnityFramework\.framework\//] },
  { id: 'unity-mono', name: 'Unity (Mono)', patterns: [/lib\/[^/]+\/libmono(bdwgc-2\.0)?\.so$/, /^assets\/bin\/Data\/Managed\/Assembly-CSharp\.dll$/, /\/Data\/Managed\/Assembly-CSharp\.dll$/] },
  { id: 'cordova', name: 'Apache Cordova', patterns: [/^assets\/www\/cordova\.js$/, /^assets\/www\/cordova_plugins\.js$/, /\.app\/www\/cordova\.js$/] },
  { id: 'capacitor', name: 'Capacitor (Ionic)', patterns: [/^assets\/capacitor\.config\.json$/, /^assets\/public\/index\.html$/, /\.app\/capacitor\.config\.json$/, /Frameworks\/Capacitor\.framework\//] },
  { id: 'godot', name: 'Godot', patterns: [/lib\/[^/]+\/libgodot_android\.so$/, /^assets\/project\.binary$/, /\.pck$/] },
  { id: 'qt', name: 'Qt', patterns: [/lib\/[^/]+\/libQt[56]Core[^/]*\.so$/] },
  { id: 'cocos2dx', name: 'Cocos2d-x', patterns: [/lib\/[^/]+\/libcocos2d(cpp|js|lua)\.so$/] },
  { id: 'unreal', name: 'Unreal Engine', patterns: [/lib\/[^/]+\/libUE4\.so$/, /lib\/[^/]+\/libUnreal\.so$/] },
  { id: 'libgdx', name: 'libGDX', patterns: [/lib\/[^/]+\/libgdx\.so$/] },
  { id: 'nativescript', name: 'NativeScript', patterns: [/lib\/[^/]+\/libNativeScript\.so$/, /^assets\/app\/bundle\.js$/] },
  { id: 'kotlin', name: 'Kotlin', patterns: [/^kotlin\/.+\.kotlin_builtins$/, /^META-INF\/[^/]+\.kotlin_module$/] },
];

/** Detect frameworks from ZIP member names. */
export function detectFrameworks(names: string[], extra: { nativeActivity?: boolean } = {}): FrameworkHit[] {
  const hits: FrameworkHit[] = [];
  for (const rule of RULES) {
    const evidence: string[] = [];
    const matched = new Set<number>();
    for (const n of names) {
      rule.patterns.forEach((p, k) => {
        if (!matched.has(k) && p.test(n)) { matched.add(k); if (!evidence.includes(n)) evidence.push(n); }
      });
      if (matched.size === rule.patterns.length) break;
    }
    if (!evidence.length) continue;
    // kotlin builtins are common in any Kotlin app; only report them, never as the main framework
    const confidence = Math.min(1, 0.55 + 0.2 * (matched.size - 1));
    hits.push({ id: rule.id, name: rule.name, confidence: Math.round(confidence * 100) / 100, evidence: evidence.slice(0, 8) });
  }
  if (extra.nativeActivity) hits.push({ id: 'native-activity', name: 'NDK NativeActivity (no Java UI code)', confidence: 0.9, evidence: ['android.app.NativeActivity in manifest'] });
  // Unity Mono is implied by managed DLLs only when IL2CPP is absent
  const il2cpp = hits.find((h) => h.id === 'unity-il2cpp');
  const mono = hits.findIndex((h) => h.id === 'unity-mono');
  if (il2cpp && mono >= 0) {
    const m = hits[mono] as FrameworkHit;
    if (!m.evidence.some((e) => /libmono/.test(e))) hits.splice(mono, 1);
  }
  return hits.sort((a, b) => b.confidence - a.confidence);
}

/** Hermes bytecode bundles start with this 8 byte magic. */
const HERMES_MAGIC = [0xc6, 0x1f, 0xbc, 0x03, 0xc1, 0x03, 0x19, 0x1f];

export function reactNativeBundleInfo(b: Uint8Array): { format: 'hermes' | 'javascript'; hermesVersion?: number; size: number } {
  if (b.length >= 12 && HERMES_MAGIC.every((x, i) => b[i] === x)) {
    const v = (b[8] as number) | ((b[9] as number) << 8) | ((b[10] as number) << 16) | ((b[11] as number) << 24);
    return { format: 'hermes', hermesVersion: v >>> 0, size: b.length };
  }
  return { format: 'javascript', size: b.length };
}

/**
 * Dart AOT snapshot hash from libapp.so (or App.framework/App). The snapshot header is
 * magic 0xdcdcf5f5, then 8 byte size, 8 byte kind, then a 32 character hex hash and a feature string.
 * The hash identifies the Dart SDK build, which maps to a Flutter release.
 */
export function dartSnapshotInfo(b: Uint8Array): { snapshotHash?: string; features?: string; offset?: number } {
  const magic = new Uint8Array([0xf5, 0xf5, 0xdc, 0xdc]);
  let at = 0;
  for (let tries = 0; tries < 16; tries++) {
    const i = indexOfBytes(b, magic, at);
    if (i < 0) break;
    const h = i + 20;
    if (h + 32 <= b.length) {
      const hash = utf8(b.subarray(h, h + 32));
      if (/^[0-9a-f]{32}$/.test(hash)) {
        let e = h + 32;
        while (e < b.length && e < h + 32 + 512 && b[e] !== 0) e++;
        return { snapshotHash: hash, features: utf8(b.subarray(h + 32, e)), offset: i };
      }
    }
    at = i + 4;
  }
  return {};
}
