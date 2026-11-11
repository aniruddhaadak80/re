// Higher level DEX analysis: class listings, search, cross references, library and obfuscation hints,
// sensitive API usage, hardcoded URLs and keys.

import { Budget } from '../bytes.js';
import { decodeCode } from './disasm.js';
import { toDescriptor, toJavaName, type ClassDef, type DexFile, type EncodedMethod } from './parse.js';

export interface MethodLoc { dex: string; class: string; method: string; signature: string; ref: string }

export interface XrefIndex {
  /** method ref -> callers */
  calls: Map<string, MethodLoc[]>;
  /** field ref -> accessors */
  fields: Map<string, { loc: MethodLoc; write: boolean }[]>;
  /** string value -> users */
  strings: Map<string, MethodLoc[]>;
  /** type descriptor -> users (new-instance, const-class, check-cast, instance-of) */
  types: Map<string, MethodLoc[]>;
  methodsIndexed: number;
  errors: number;
  truncated: boolean;
}

const xrefCache = new WeakMap<DexFile, XrefIndex>();
const MAX_PER_KEY = 500;

function push<T>(m: Map<string, T[]>, k: string, v: T): void {
  const a = m.get(k);
  if (!a) m.set(k, [v]);
  else if (a.length < MAX_PER_KEY) a.push(v);
}

export function* allMethods(dex: DexFile): Generator<{ cd: ClassDef; m: EncodedMethod; direct: boolean }> {
  for (const cd of dex.classes) {
    let data;
    try { data = dex.classData(cd); } catch { continue; }
    for (const m of data.directMethods) yield { cd, m, direct: true };
    for (const m of data.virtualMethods) yield { cd, m, direct: false };
  }
}

export function locOf(dex: DexFile, cd: ClassDef, m: EncodedMethod): MethodLoc {
  const id = dex.method(m.methodIdx);
  const signature = `(${id.proto.params.join('')})${id.proto.ret}`;
  return { dex: dex.name, class: cd.name, method: id.name, signature, ref: `${cd.name}->${id.name}${signature}` };
}

/** Build (and cache) call, field, string and type cross references for one DEX. */
export function xrefIndex(dex: DexFile, budgetMs = 30_000): XrefIndex {
  const cached = xrefCache.get(dex);
  if (cached) return cached;
  const idx: XrefIndex = { calls: new Map(), fields: new Map(), strings: new Map(), types: new Map(), methodsIndexed: 0, errors: 0, truncated: false };
  const budget = new Budget(budgetMs);
  for (const { cd, m } of allMethods(dex)) {
    if (!m.codeOff) continue;
    try { budget.check('cross reference indexing'); } catch { idx.truncated = true; break; }
    const loc = locOf(dex, cd, m);
    try {
      const ci = dex.code(m.codeOff);
      if (!ci) continue;
      for (const i of decodeCode(dex, ci)) {
        if (i.idx === undefined) continue;
        switch (i.op.ref) {
          case 'method': push(idx.calls, dex.methodRef(i.idx), loc); break;
          case 'field': push(idx.fields, dex.fieldRef(i.idx), { loc, write: /put/.test(i.op.name) }); break;
          case 'string': push(idx.strings, dex.string(i.idx), loc); break;
          case 'type': push(idx.types, dex.type(i.idx), loc); break;
          default: break;
        }
      }
      idx.methodsIndexed++;
    } catch { idx.errors++; }
  }
  xrefCache.set(dex, idx);
  return idx;
}

// ------------------------------------------------------------------ libraries

/** Package prefixes of common Android SDKs and libraries, in slash form. */
export const LIBRARIES: { prefix: string; name: string; category: string }[] = [
  { prefix: 'okhttp3/', name: 'OkHttp 3/4', category: 'network' },
  { prefix: 'com/squareup/okhttp/', name: 'OkHttp 2', category: 'network' },
  { prefix: 'okio/', name: 'Okio', category: 'io' },
  { prefix: 'retrofit2/', name: 'Retrofit 2', category: 'network' },
  { prefix: 'com/android/volley/', name: 'Volley', category: 'network' },
  { prefix: 'io/ktor/', name: 'Ktor', category: 'network' },
  { prefix: 'com/google/gson/', name: 'Gson', category: 'serialization' },
  { prefix: 'com/squareup/moshi/', name: 'Moshi', category: 'serialization' },
  { prefix: 'com/fasterxml/jackson/', name: 'Jackson', category: 'serialization' },
  { prefix: 'kotlinx/serialization/', name: 'kotlinx.serialization', category: 'serialization' },
  { prefix: 'com/google/protobuf/', name: 'Protocol Buffers', category: 'serialization' },
  { prefix: 'com/google/firebase/', name: 'Firebase', category: 'backend' },
  { prefix: 'com/google/firebase/crashlytics/', name: 'Firebase Crashlytics', category: 'crash-reporting' },
  { prefix: 'com/google/firebase/analytics/', name: 'Firebase Analytics', category: 'analytics' },
  { prefix: 'com/google/firebase/messaging/', name: 'Firebase Cloud Messaging', category: 'push' },
  { prefix: 'com/google/android/gms/ads/', name: 'Google Mobile Ads (AdMob)', category: 'ads' },
  { prefix: 'com/google/android/gms/', name: 'Google Play Services', category: 'platform' },
  { prefix: 'com/google/android/play/core/', name: 'Play Core', category: 'platform' },
  { prefix: 'com/google/android/material/', name: 'Material Components', category: 'ui' },
  { prefix: 'com/google/android/exoplayer2/', name: 'ExoPlayer', category: 'media' },
  { prefix: 'androidx/media3/', name: 'Media3', category: 'media' },
  { prefix: 'com/google/zxing/', name: 'ZXing', category: 'barcode' },
  { prefix: 'com/google/mlkit/', name: 'ML Kit', category: 'ml' },
  { prefix: 'org/tensorflow/lite/', name: 'TensorFlow Lite', category: 'ml' },
  { prefix: 'com/facebook/react/', name: 'React Native', category: 'framework' },
  { prefix: 'com/facebook/hermes/', name: 'Hermes', category: 'framework' },
  { prefix: 'com/facebook/soloader/', name: 'SoLoader', category: 'framework' },
  { prefix: 'com/facebook/', name: 'Facebook SDK', category: 'social' },
  { prefix: 'io/flutter/', name: 'Flutter embedding', category: 'framework' },
  { prefix: 'mono/android/', name: 'Xamarin / .NET for Android', category: 'framework' },
  { prefix: 'crc64', name: 'Xamarin generated wrappers', category: 'framework' },
  { prefix: 'com/unity3d/', name: 'Unity', category: 'framework' },
  { prefix: 'org/apache/cordova/', name: 'Apache Cordova', category: 'framework' },
  { prefix: 'com/getcapacitor/', name: 'Capacitor', category: 'framework' },
  { prefix: 'org/godotengine/', name: 'Godot', category: 'framework' },
  { prefix: 'com/badlogic/gdx/', name: 'libGDX', category: 'framework' },
  { prefix: 'kotlin/', name: 'Kotlin stdlib', category: 'language' },
  { prefix: 'kotlinx/coroutines/', name: 'Kotlin coroutines', category: 'language' },
  { prefix: 'androidx/compose/', name: 'Jetpack Compose', category: 'ui' },
  { prefix: 'androidx/room/', name: 'Room', category: 'database' },
  { prefix: 'androidx/work/', name: 'WorkManager', category: 'platform' },
  { prefix: 'androidx/', name: 'AndroidX', category: 'platform' },
  { prefix: 'android/support/', name: 'Android Support Library', category: 'platform' },
  { prefix: 'dagger/', name: 'Dagger', category: 'di' },
  { prefix: 'com/google/dagger/', name: 'Dagger', category: 'di' },
  { prefix: 'org/koin/', name: 'Koin', category: 'di' },
  { prefix: 'io/reactivex/', name: 'RxJava', category: 'reactive' },
  { prefix: 'rx/', name: 'RxJava 1', category: 'reactive' },
  { prefix: 'com/bumptech/glide/', name: 'Glide', category: 'images' },
  { prefix: 'com/squareup/picasso/', name: 'Picasso', category: 'images' },
  { prefix: 'coil/', name: 'Coil', category: 'images' },
  { prefix: 'com/facebook/fresco/', name: 'Fresco', category: 'images' },
  { prefix: 'io/realm/', name: 'Realm', category: 'database' },
  { prefix: 'net/sqlcipher/', name: 'SQLCipher', category: 'database' },
  { prefix: 'org/greenrobot/', name: 'greenrobot (EventBus/greenDAO)', category: 'misc' },
  { prefix: 'com/jakewharton/timber/', name: 'Timber', category: 'logging' },
  { prefix: 'timber/log/', name: 'Timber', category: 'logging' },
  { prefix: 'io/sentry/', name: 'Sentry', category: 'crash-reporting' },
  { prefix: 'com/bugsnag/', name: 'Bugsnag', category: 'crash-reporting' },
  { prefix: 'org/acra/', name: 'ACRA', category: 'crash-reporting' },
  { prefix: 'com/appsflyer/', name: 'AppsFlyer', category: 'analytics' },
  { prefix: 'com/adjust/sdk/', name: 'Adjust', category: 'analytics' },
  { prefix: 'com/mixpanel/', name: 'Mixpanel', category: 'analytics' },
  { prefix: 'com/amplitude/', name: 'Amplitude', category: 'analytics' },
  { prefix: 'com/segment/', name: 'Segment', category: 'analytics' },
  { prefix: 'com/onesignal/', name: 'OneSignal', category: 'push' },
  { prefix: 'com/applovin/', name: 'AppLovin', category: 'ads' },
  { prefix: 'com/ironsource/', name: 'ironSource', category: 'ads' },
  { prefix: 'com/mopub/', name: 'MoPub', category: 'ads' },
  { prefix: 'com/vungle/', name: 'Vungle', category: 'ads' },
  { prefix: 'com/stripe/', name: 'Stripe', category: 'payments' },
  { prefix: 'com/paypal/', name: 'PayPal', category: 'payments' },
  { prefix: 'com/braintreepayments/', name: 'Braintree', category: 'payments' },
  { prefix: 'org/bouncycastle/', name: 'Bouncy Castle', category: 'crypto' },
  { prefix: 'org/spongycastle/', name: 'Spongy Castle', category: 'crypto' },
  { prefix: 'org/conscrypt/', name: 'Conscrypt', category: 'crypto' },
  { prefix: 'com/google/crypto/tink/', name: 'Tink', category: 'crypto' },
  { prefix: 'org/apache/commons/', name: 'Apache Commons', category: 'misc' },
  { prefix: 'org/apache/http/', name: 'Apache HttpClient', category: 'network' },
  { prefix: 'org/jsoup/', name: 'jsoup', category: 'parsing' },
  { prefix: 'org/json/', name: 'org.json', category: 'serialization' },
  { prefix: 'com/google/common/', name: 'Guava', category: 'misc' },
  { prefix: 'org/slf4j/', name: 'SLF4J', category: 'logging' },
  { prefix: 'io/grpc/', name: 'gRPC', category: 'network' },
  { prefix: 'com/apollographql/', name: 'Apollo GraphQL', category: 'network' },
  { prefix: 'org/webrtc/', name: 'WebRTC', category: 'media' },
  { prefix: 'com/tencent/', name: 'Tencent SDK', category: 'social' },
  { prefix: 'com/huawei/hms/', name: 'Huawei Mobile Services', category: 'platform' },
  { prefix: 'com/topjohnwu/superuser/', name: 'libsu (root)', category: 'root' },
  { prefix: 'de/robv/android/xposed/', name: 'Xposed API', category: 'hooking' },
  { prefix: 'com/scottyab/rootbeer/', name: 'RootBeer (root detection)', category: 'protection' },
  { prefix: 'com/secneo/', name: 'Bangcle packer', category: 'packer' },
  { prefix: 'com/qihoo/util/', name: 'Qihoo 360 Jiagu packer', category: 'packer' },
  { prefix: 'com/tencent/StubShell/', name: 'Tencent Legu packer', category: 'packer' },
  { prefix: 'com/baidu/protect/', name: 'Baidu packer', category: 'packer' },
  { prefix: 'com/ijiami/', name: 'Ijiami packer', category: 'packer' },
  { prefix: 'com/shell/SuperApplication', name: 'generic shell packer', category: 'packer' },
];

export interface LibraryHit { name: string; prefix: string; category: string; classes: number }

/** Detect libraries by package prefix. More specific prefixes win; each class counts once. */
export function detectLibraries(classNames: Iterable<string>): LibraryHit[] {
  const sorted = [...LIBRARIES].sort((a, b) => b.prefix.length - a.prefix.length);
  const hits = new Map<string, LibraryHit>();
  for (const desc of classNames) {
    const n = desc.startsWith('L') ? desc.slice(1) : desc;
    const lib = sorted.find((l) => n.startsWith(l.prefix));
    if (!lib) continue;
    const h = hits.get(lib.name + lib.prefix);
    if (h) h.classes++;
    else hits.set(lib.name + lib.prefix, { name: lib.name, prefix: lib.prefix.replace(/\//g, '.'), category: lib.category, classes: 1 });
  }
  return [...hits.values()].sort((a, b) => b.classes - a.classes);
}

// ------------------------------------------------------------------ obfuscation

export interface ObfuscationHints {
  classes: number;
  /** classes whose simple name is 1 to 2 characters */
  shortNames: number;
  shortRatio: number;
  /** distinct single-letter package segments, like a/b/c */
  shortPackages: number;
  /** names using characters outside Java identifier ASCII */
  unusualNames: number;
  likelyObfuscated: boolean;
  tool?: string;
  notes: string[];
}

export function obfuscationHints(classNames: string[], strings: Iterable<string> = []): ObfuscationHints {
  let short = 0, unusual = 0;
  const shortPkgs = new Set<string>();
  const app = classNames.filter((c) => !LIBRARIES.some((l) => c.startsWith(`L${l.prefix}`)) && !c.startsWith('Landroid/'));
  for (const c of app) {
    const body = c.slice(1, -1);
    const parts = body.split('/');
    const simple = (parts[parts.length - 1] ?? '').split('$')[0] ?? '';
    if (simple.length <= 2) short++;
    for (const p of parts.slice(0, -1)) if (p.length === 1) shortPkgs.add(p);
    if (/[^\x21-\x7e]/.test(body)) unusual++;
  }
  const ratio = app.length ? short / app.length : 0;
  const notes: string[] = [];
  let tool: string | undefined;
  for (const s of strings) {
    if (/^~~R8\{/.test(s)) { tool = 'R8'; notes.push(`R8 marker: ${s.slice(0, 120)}`); break; }
  }
  if (ratio > 0.3) notes.push(`${Math.round(ratio * 100)}% of app classes have 1 or 2 character names`);
  if (shortPkgs.size > 3) notes.push(`${shortPkgs.size} single letter package names`);
  if (unusual > 0) notes.push(`${unusual} class names use unusual characters, a sign of a commercial obfuscator`);
  return {
    classes: app.length, shortNames: short, shortRatio: Math.round(ratio * 1000) / 1000, shortPackages: shortPkgs.size,
    unusualNames: unusual, likelyObfuscated: ratio > 0.3 || unusual > 10, ...(tool ? { tool } : {}), notes,
  };
}

// ------------------------------------------------------------------ sensitive APIs

export interface ApiRule { id: string; title: string; category: string; severity: 'info' | 'low' | 'medium' | 'high'; match: string; attack?: string }

/** Method ref prefixes (class->name) that mark interesting behaviour. */
export const API_RULES: ApiRule[] = [
  { id: 'reflection-forname', title: 'Reflection: Class.forName', category: 'reflection', severity: 'low', match: 'Ljava/lang/Class;->forName' },
  { id: 'reflection-invoke', title: 'Reflection: Method.invoke', category: 'reflection', severity: 'low', match: 'Ljava/lang/reflect/Method;->invoke' },
  { id: 'reflection-getmethod', title: 'Reflection: getDeclaredMethod', category: 'reflection', severity: 'low', match: 'Ljava/lang/Class;->getDeclaredMethod' },
  { id: 'dynload-dexclassloader', title: 'Dynamic code loading: DexClassLoader', category: 'dynamic-loading', severity: 'medium', match: 'Ldalvik/system/DexClassLoader;-><init>', attack: 'T1407' },
  { id: 'dynload-pathclassloader', title: 'Dynamic code loading: PathClassLoader', category: 'dynamic-loading', severity: 'low', match: 'Ldalvik/system/PathClassLoader;-><init>', attack: 'T1407' },
  { id: 'dynload-inmemory', title: 'Dynamic code loading: InMemoryDexClassLoader', category: 'dynamic-loading', severity: 'high', match: 'Ldalvik/system/InMemoryDexClassLoader;-><init>', attack: 'T1407' },
  { id: 'dynload-dexfile', title: 'Dynamic code loading: DexFile.loadDex', category: 'dynamic-loading', severity: 'medium', match: 'Ldalvik/system/DexFile;->loadDex', attack: 'T1407' },
  { id: 'native-loadlibrary', title: 'Native library load: System.loadLibrary', category: 'native', severity: 'info', match: 'Ljava/lang/System;->loadLibrary' },
  { id: 'native-load', title: 'Native library load by path: System.load', category: 'native', severity: 'low', match: 'Ljava/lang/System;->load(' },
  { id: 'exec-runtime', title: 'Shell command: Runtime.exec', category: 'exec', severity: 'medium', match: 'Ljava/lang/Runtime;->exec', attack: 'T1603' },
  { id: 'exec-processbuilder', title: 'Shell command: ProcessBuilder', category: 'exec', severity: 'medium', match: 'Ljava/lang/ProcessBuilder;->start' },
  { id: 'webview-js-interface', title: 'WebView JavaScript bridge: addJavascriptInterface', category: 'webview', severity: 'medium', match: 'Landroid/webkit/WebView;->addJavascriptInterface' },
  { id: 'webview-js-enabled', title: 'WebView JavaScript enabled', category: 'webview', severity: 'info', match: 'Landroid/webkit/WebSettings;->setJavaScriptEnabled' },
  { id: 'webview-file-access', title: 'WebView file access from file URLs', category: 'webview', severity: 'medium', match: 'Landroid/webkit/WebSettings;->setAllowUniversalAccessFromFileURLs' },
  { id: 'crypto-cipher', title: 'Cipher.getInstance', category: 'crypto', severity: 'info', match: 'Ljavax/crypto/Cipher;->getInstance' },
  { id: 'crypto-secretkeyspec', title: 'Hardcoded key material may reach SecretKeySpec', category: 'crypto', severity: 'low', match: 'Ljavax/crypto/spec/SecretKeySpec;-><init>' },
  { id: 'tls-hostname-verifier', title: 'Custom HostnameVerifier', category: 'tls', severity: 'medium', match: 'Ljavax/net/ssl/HttpsURLConnection;->setDefaultHostnameVerifier' },
  { id: 'tls-sslcontext', title: 'Custom SSLContext init (possible custom TrustManager)', category: 'tls', severity: 'low', match: 'Ljavax/net/ssl/SSLContext;->init' },
  { id: 'sms-send', title: 'Sends SMS: SmsManager.sendTextMessage', category: 'sms', severity: 'high', match: 'Landroid/telephony/SmsManager;->sendTextMessage', attack: 'T1582' },
  { id: 'device-id', title: 'Reads device identifiers: getDeviceId / getImei', category: 'privacy', severity: 'medium', match: 'Landroid/telephony/TelephonyManager;->getDeviceId' },
  { id: 'device-imei', title: 'Reads IMEI', category: 'privacy', severity: 'medium', match: 'Landroid/telephony/TelephonyManager;->getImei' },
  { id: 'android-id', title: 'Reads Settings.Secure (ANDROID_ID and similar)', category: 'privacy', severity: 'info', match: 'Landroid/provider/Settings$Secure;->getString' },
  { id: 'location', title: 'Requests location updates', category: 'privacy', severity: 'info', match: 'Landroid/location/LocationManager;->requestLocationUpdates' },
  { id: 'clipboard', title: 'Reads clipboard', category: 'privacy', severity: 'low', match: 'Landroid/content/ClipboardManager;->getPrimaryClip' },
  { id: 'camera', title: 'Opens camera', category: 'privacy', severity: 'info', match: 'Landroid/hardware/Camera;->open' },
  { id: 'audio-record', title: 'Records audio', category: 'privacy', severity: 'medium', match: 'Landroid/media/AudioRecord;-><init>' },
  { id: 'accessibility', title: 'Performs accessibility actions', category: 'accessibility', severity: 'medium', match: 'Landroid/view/accessibility/AccessibilityNodeInfo;->performAction' },
  { id: 'package-install', title: 'Installs packages: PackageInstaller', category: 'install', severity: 'medium', match: 'Landroid/content/pm/PackageInstaller;->createSession' },
  { id: 'device-admin', title: 'Device admin lockNow / wipeData', category: 'device-admin', severity: 'high', match: 'Landroid/app/admin/DevicePolicyManager;->wipeData' },
  { id: 'base64-decode', title: 'Base64 decoding', category: 'encoding', severity: 'info', match: 'Landroid/util/Base64;->decode' },
  { id: 'log', title: 'Writes to logcat', category: 'logging', severity: 'info', match: 'Landroid/util/Log;->d' },
  { id: 'su-check', title: 'Root or emulator checks via Build fields', category: 'anti-analysis', severity: 'info', match: 'Landroid/os/Debug;->isDebuggerConnected' },
];

export interface ApiHit { rule: ApiRule; target: string; callers: MethodLoc[] }

export function sensitiveApis(index: XrefIndex, maxCallers = 20): ApiHit[] {
  const out: ApiHit[] = [];
  for (const rule of API_RULES) {
    for (const [ref, callers] of index.calls) {
      if (!ref.startsWith(rule.match)) continue;
      out.push({ rule, target: ref, callers: callers.slice(0, maxCallers) });
    }
  }
  return out;
}

// ------------------------------------------------------------------ strings: urls and keys

export interface SecretPattern { id: string; title: string; re: RegExp; severity: 'low' | 'medium' | 'high' }

/** Linear-time patterns only: bounded quantifiers, no nested repetition. */
export const SECRET_PATTERNS: SecretPattern[] = [
  { id: 'aws-access-key', title: 'AWS access key id', re: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/, severity: 'high' },
  { id: 'google-api-key', title: 'Google API key', re: /\bAIza[0-9A-Za-z_-]{35}\b/, severity: 'medium' },
  { id: 'firebase-db', title: 'Firebase Realtime Database URL', re: /\bhttps:\/\/[a-z0-9-]{1,80}\.firebaseio\.com(?=$|[^\w.-])/, severity: 'low' },
  { id: 'private-key', title: 'PEM private key', re: /-----BEGIN (RSA |EC |DSA |OPENSSH |)PRIVATE KEY-----/, severity: 'high' },
  { id: 'slack-token', title: 'Slack token', re: /\bxox[abprs]-[0-9A-Za-z-]{10,80}\b/, severity: 'high' },
  { id: 'stripe-secret', title: 'Stripe secret key', re: /\b[sr]k_live_[0-9A-Za-z]{16,99}\b/, severity: 'high' },
  { id: 'stripe-publishable', title: 'Stripe publishable key', re: /\bpk_live_[0-9A-Za-z]{16,99}\b/, severity: 'low' },
  { id: 'github-token', title: 'GitHub token', re: /\bgh[pousr]_[0-9A-Za-z]{36}\b/, severity: 'high' },
  { id: 'jwt', title: 'JSON Web Token', re: /\beyJ[0-9A-Za-z_-]{8,400}\.eyJ[0-9A-Za-z_-]{8,2000}\.[0-9A-Za-z_-]{8,600}/, severity: 'medium' },
  { id: 'twilio-sid', title: 'Twilio account SID', re: /\bAC[0-9a-f]{32}\b/, severity: 'low' },
  { id: 'sendgrid', title: 'SendGrid API key', re: /\bSG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}\b/, severity: 'high' },
  { id: 'mailgun', title: 'Mailgun API key', re: /\bkey-[0-9a-z]{32}\b/, severity: 'medium' },
  { id: 'gcp-service-account', title: 'Google service account JSON', re: /"type":\s{0,4}"service_account"/, severity: 'high' },
];

const URL_RE = /\b(?:https?|wss?|ftp):\/\/[^\s"'<>\\^`{|}]{3,300}/g;

export interface StringHit { value: string; kind: string; title: string; severity: string; users: MethodLoc[] }

/** Scan the DEX string table for URLs and key-like values, with the methods that use each. */
export function scanStrings(dex: DexFile, index?: XrefIndex, limit = 1000): { urls: StringHit[]; secrets: StringHit[] } {
  const urls: StringHit[] = [];
  const secrets: StringHit[] = [];
  const seen = new Set<string>();
  const n = Math.min(dex.stringCount, 2_000_000);
  for (let i = 0; i < n; i++) {
    const s = dex.string(i);
    if (s.length < 8 || s.length > 8192) continue;
    const users = index?.strings.get(s)?.slice(0, 10) ?? [];
    if (urls.length < limit && s.includes('://')) {
      URL_RE.lastIndex = 0;
      let m: RegExpExecArray | null;
      let k = 0;
      while ((m = URL_RE.exec(s)) && k++ < 20) {
        const u = m[0];
        if (seen.has(u) || /^https?:\/\/(schemas\.android\.com|www\.w3\.org|ns\.adobe\.com|xml\.org|apache\.org\/xml)/.test(u)) continue;
        seen.add(u);
        urls.push({ value: u, kind: 'url', title: 'URL', severity: 'info', users });
      }
    }
    if (secrets.length < limit) {
      for (const p of SECRET_PATTERNS) {
        const m = p.re.exec(s);
        if (m) secrets.push({ value: m[0], kind: p.id, title: p.title, severity: p.severity, users });
      }
    }
  }
  return { urls, secrets };
}

// ------------------------------------------------------------------ JNI names

function mangle(s: string): string {
  let out = '';
  for (const ch of s) {
    const c = ch.codePointAt(0) as number;
    if (ch === '/' || ch === '.') out += '_';
    else if (ch === '_') out += '_1';
    else if (ch === ';') out += '_2';
    else if (ch === '[') out += '_3';
    else if ((c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a)) out += ch;
    else out += `_0${c.toString(16).padStart(4, '0')}`;
  }
  return out;
}

/** JNI short and long symbol names for a native method. */
export function jniNames(classDesc: string, method: string, params: string[]): { short: string; long: string } {
  const cls = classDesc.startsWith('L') ? classDesc.slice(1, -1) : classDesc;
  const short = `Java_${mangle(cls)}_${mangle(method)}`;
  return { short, long: `${short}__${mangle(params.join(''))}` };
}

export interface NativeMethod { class: string; method: string; signature: string; jni: string; jniLong: string }

export function nativeMethods(dex: DexFile, limit = 5000): NativeMethod[] {
  const out: NativeMethod[] = [];
  for (const { cd, m } of allMethods(dex)) {
    if (!(m.access & 0x100)) continue;
    const id = dex.method(m.methodIdx);
    const j = jniNames(cd.name, id.name, id.proto.params);
    out.push({ class: toJavaName(cd.name), method: id.name, signature: `(${id.proto.params.join('')})${id.proto.ret}`, jni: j.short, jniLong: j.long });
    if (out.length >= limit) break;
  }
  return out;
}

// ------------------------------------------------------------------ finders

export interface MemberMatch { kind: 'class' | 'method' | 'field' | 'string'; dex: string; class: string; name?: string; signature?: string; value?: string }

/** Case-insensitive substring search over class, method, field names and strings. */
export function searchDex(dexes: DexFile[], query: string, kinds: MemberMatch['kind'][] = ['class', 'method', 'field', 'string'], limit = 200): MemberMatch[] {
  const q = query.toLowerCase();
  const qd = toDescriptor(query).toLowerCase();
  const out: MemberMatch[] = [];
  const full = (): boolean => out.length >= limit;
  for (const dex of dexes) {
    if (kinds.includes('class')) {
      for (const cd of dex.classes) {
        const n = cd.name.toLowerCase();
        if (n.includes(q) || n.includes(qd.slice(0, -1)) || toJavaName(cd.name).toLowerCase().includes(q)) out.push({ kind: 'class', dex: dex.name, class: cd.name });
        if (full()) return out;
      }
    }
    if (kinds.includes('method') || kinds.includes('field')) {
      for (const cd of dex.classes) {
        let data;
        try { data = dex.classData(cd); } catch { continue; }
        if (kinds.includes('method')) {
          for (const m of [...data.directMethods, ...data.virtualMethods]) {
            const id = dex.method(m.methodIdx);
            if (id.name.toLowerCase().includes(q)) out.push({ kind: 'method', dex: dex.name, class: cd.name, name: id.name, signature: `(${id.proto.params.join('')})${id.proto.ret}` });
            if (full()) return out;
          }
        }
        if (kinds.includes('field')) {
          for (const f of [...data.staticFields, ...data.instanceFields]) {
            const fi = dex.field(f.fieldIdx);
            if (fi.name.toLowerCase().includes(q)) out.push({ kind: 'field', dex: dex.name, class: cd.name, name: fi.name, signature: fi.type });
            if (full()) return out;
          }
        }
      }
    }
    if (kinds.includes('string')) {
      const n = Math.min(dex.stringCount, 2_000_000);
      for (let i = 0; i < n; i++) {
        const s = dex.string(i);
        if (s.toLowerCase().includes(q)) {
          const users = xrefIndex(dex).strings.get(s) ?? [];
          if (users.length === 0) out.push({ kind: 'string', dex: dex.name, class: '', value: s });
          for (const u of users.slice(0, 20)) {
            out.push({ kind: 'string', dex: dex.name, class: u.class, name: u.method, signature: u.signature, value: s });
            if (full()) return out;
          }
        }
        if (full()) return out;
      }
    }
  }
  return out;
}

/** Find a method in a set of DEX files. `method` can be a name or name plus signature like add(II)I. */
export function findMethod(dexes: DexFile[], className: string, method: string): { dex: DexFile; cd: ClassDef; m: EncodedMethod; direct: boolean }[] {
  const desc = toDescriptor(className);
  const paren = method.indexOf('(');
  const name = paren >= 0 ? method.slice(0, paren) : method;
  const sig = paren >= 0 ? method.slice(paren) : undefined;
  const out: { dex: DexFile; cd: ClassDef; m: EncodedMethod; direct: boolean }[] = [];
  for (const dex of dexes) {
    const cd = dex.classByName(desc);
    if (!cd) continue;
    const data = dex.classData(cd);
    for (const [list, direct] of [[data.directMethods, true], [data.virtualMethods, false]] as const) {
      for (const m of list) {
        const id = dex.method(m.methodIdx);
        if (id.name !== name) continue;
        if (sig && `(${id.proto.params.join('')})${id.proto.ret}` !== sig) continue;
        out.push({ dex, cd, m, direct });
      }
    }
  }
  return out;
}
