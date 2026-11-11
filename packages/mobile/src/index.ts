// @revlens/mobile: Android, Java and iOS app reverse engineering in pure TypeScript.
// Browser and Web Worker safe. Node-only helpers live in ./node.

export { ANALYZERS, mobileApkAnalyzer, mobileDexAnalyzer, mobileClassAnalyzer, mobileIpaAnalyzer, mobileIl2cppAnalyzer } from './analyzers.js';
export {
  TOOLS, dexesOf, mobileManifest, mobileSigning, mobileDexClasses, mobileDexMethod, mobileDexSearch, mobileDexXrefs,
  mobileJavaClass, mobileIpaInfo, mobileAppFramework, mobileIl2cppTypes, mobileNativeLibs, mobileApkReport,
  type Tool, type ToolInputSpec,
} from './tools.js';
export { CLI_COMMANDS, setCliOutput, type CliCommand } from './cli.js';
export { setFileReader, loadInput, type FileReader } from './input.js';

// format level APIs
export { openZip, readEntry, type ZipArchive, type ZipEntry } from './zip.js';
export { parseAxml, axmlToXml, parseResourceTable, parseStringPool, isAxml, resolveRef, type AxmlDocument, type XmlNode, type ResourceTable } from './axml.js';
export { parseManifest, interpretManifest, interpretNetworkSecurityConfig, type ManifestInfo, type Component, type DeepLink, type NetworkSecurityConfig } from './manifest.js';
export { permissionInfo, PERMISSIONS, type PermissionInfo, type ProtectionLevel } from './permissions.js';
export { apkSigning, type SigningInfo } from './signing.js';
export { parseCertificate, pkcs7Certificates, type CertInfo } from './der.js';
export { analyzeApk, loadDexes, readManifest, manifestFindings, signingFindings, type ApkReport, type ApkOptions } from './apk.js';
export { DexFile, openDex, isDex, toDescriptor, toJavaName, type ClassDef, type CodeItem } from './dex/parse.js';
export { decodeCode, renderClass, renderMethod, renderMethodBody, smaliString, accessString, type Insn } from './dex/disasm.js';
export { OPS } from './dex/opcodes.js';
export { xrefIndex, searchDex, findMethod, detectLibraries, obfuscationHints, sensitiveApis, scanStrings, nativeMethods, jniNames, LIBRARIES, API_RULES, SECRET_PATTERNS } from './dex/analysis.js';
export { parseClass, isClassFile, descToJava, type ClassFile } from './jvm/classfile.js';
export { javap, decodeJvm, renderJvmCode, classDecl, methodDecl, fieldDecl, javaFloat } from './jvm/disasm.js';
export { parseElfDynamic, isElf, type ElfSummary } from './native.js';
export { parsePlist, parseBinaryPlist, parseXmlPlist, isBinaryPlist, type PlistValue } from './ios/plist.js';
export { parseMachoSlices, isMacho, type MachoSlice, type CodeSignature } from './ios/macho.js';
export { analyzeIpa, findAppRoot, machoEntitlements, provisioningPlist, type IpaInfo } from './ios/ipa.js';
export { detectFrameworks, dartSnapshotInfo, reactNativeBundleInfo, type FrameworkHit } from './framework.js';
export { parseIl2cppMetadata, isIl2cppMetadata, type Il2cppParsed } from './il2cpp.js';
export { ParseError } from './bytes.js';
