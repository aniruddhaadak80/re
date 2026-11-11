---
title: Windows and Apple artifacts
description: Read registry hives, Prefetch files, Jump Lists and OLE compound files from Windows, and NSKeyedArchiver plists, compiled nibs and Assets.car catalogs from Apple platforms, offline and in pure TypeScript.
order: 24.6
---

# Windows and Apple artifacts

Part of `@revlens/extras`. These readers work on copies of files, offline, in Node or in a browser Web Worker. Nothing is executed and no system API is called, so you can read a Windows hive on a Mac or a nib on Linux.

## Windows

| Tool | CLI | What you get |
|---|---|---|
| `x_registry_hive` | `x-registry` | hive header, one key with subkeys and decoded values, or a paged recursive key list |
| `x_prefetch` | `x-prefetch` | executable name, path hash, run count, last run times, loaded files and volumes, Windows XP to 11 |
| `x_jump_list` | `x-jumplist` | DestList entries of automatic Jump Lists with their embedded shell links, or the links of custom destinations |
| `x_ole_compound` | `x-ole` | OLE compound file directory, or the hex of one stream |
| `x_lnk_inspect` | `x-lnk` | Windows shortcut header, target IDList, link info and strings |

```sh
revlens x-registry NTUSER.DAT --key 'Software\Microsoft\Windows\CurrentVersion\Run'
revlens x-prefetch CHROME.EXE-1A2B3C4D.pf
revlens x-jumplist 5f7b5f1e01b83767.automaticDestinations-ms
```

Windows 10 and later compress Prefetch files with LZXPRESS Huffman (the `MAM` header). The decoder is included.

## Apple

| Tool | CLI | What you get |
|---|---|---|
| `x_keyed_archive` | `x-keyed-archive` | an NSKeyedArchiver archive (binary or XML plist) resolved to plain JSON with class names |
| `x_nib` | `x-nib` | a compiled nib (NIBArchive or keyed): classes, strings, outlets and actions, custom classes, raw objects |
| `x_asset_catalog` | `x-assets-car` | Assets.car header, facets, appearances and renditions |
| `x_macho_inspect` | `x-macho` | load commands, dylibs, code signature and entitlements |
| `x_apple_ips` | `x-ips` | `.ips` crash reports with frames mapped to images |

Outlets and actions in a nib tell you which controls are wired to which methods, a quick way into an app's UI code before you open a disassembler. For Swift symbol names in the same app, see [Swift demangling](swift-demangling.md).

## How it was checked

| Area | Reference |
|---|---|
| Registry hives | regipy 6.5.0: key and value totals and decoded values |
| Prefetch | windowsprefetch 4.0.3 on XP, Vista, 7, 8 and 10 files; the LZXPRESS Huffman output is byte identical to dissect.util |
| Jump Lists and OLE | olefile 0.47 and LnkParse3 1.6.0: DestList and embedded links |
| NSKeyedArchiver | swift-corelibs-foundation archives decoded by NSKeyedUnArchiver 1.5.2 and plistlib |
| Nibs | Sparkle nibs compiled by ibtool, read by nibarchive 1.1.0 |
| Assets.car | the Maccy catalog against its source catalog and the CARHEADER rendition count |

Every parser is also fed random bytes, truncations and byte flipped real files with fast-check.

## Limits

- Registry transaction logs are not replayed, so a dirty hive shows its last flushed state.
- Assets.car renditions are listed with their metadata; image pixels are not decoded.
- Nibs list objects and connections; they are not rendered as a UI.
