---
title: Rules (yara-lite)
description: The full yara-lite language reference, with examples that are tested against real files.
order: 5
---

# Rules (yara-lite)

RevLens includes yara-lite, a pure TypeScript engine for a practical subset of the [YARA](https://github.com/VirusTotal/yara) rule language. It needs no native `yara` binary and no WASM build, so the same rules run in the browser, the CLI, the MCP server and CI.

If you already write YARA, you will feel at home. Most rules built from text strings, hex patterns and simple conditions work without changes. This page lists exactly what is supported, and every example on it is run against the real file named above it in our docs check.

## Where rules run

- Every analysis runs the built in starter pack (13 rules).
- Add your own with `--rules my.yar` on the CLI, `rules` in `AnalyzeOptions`, or the `scan_rules` MCP tool.
- Call the engine directly with `scanRules(bytes, ruleText)`. It returns one `RuleMatch` per rule that matched, with up to five hits per string, each with an offset, length and printable snippet.

```ts
import { scanRules } from '@revlens/core';

const matches = scanRules(bytes, `rule Has_jQuery { strings: $a = "jQuery" condition: $a }`);
// [{ rule: 'Has_jQuery', tags: [], meta: {}, strings: [{ id: '$a', offset: 4, length: 6, snippet: 'jQuery' }, ...] }]
```

A syntax error throws an `Error` whose message starts with the rule name, for example `rule Broken: empty condition`.

## Rule structure

```text
rule Name : tag1 tag2
{
  meta:
    description = "What this rule means"
    severity = "high"
    attack = "T1055"
  strings:
    $a = "text"
    $b = { 4D 5A }
    $c = /regex/
  condition:
    $a and ($b or $c)
}
```

- **Name** is letters, digits and underscores.
- **Tags** after a colon are optional and end up in `RuleMatch.tags` and in the finding's tags.
- **meta** is optional. Values can be quoted strings or bare words. RevLens reads three keys: `description` becomes the finding detail, `severity` (`info`, `low`, `medium`, `high`, `critical`) becomes the finding severity, and `attack` becomes its ATT&CK id. A rule without a valid severity is reported as `medium`.
- **strings** is optional. A rule with only a condition can still test `filesize` or bytes at an offset.
- **condition** defaults to `any of them` when it is missing.
- `//` line comments and `/* */` block comments are allowed anywhere. The `private` and `global` keywords are accepted but have no special meaning yet.

## Text strings

```text
$a = "exact text"
$b = "Kernel32.DLL" nocase
$c = "esbuild" wide
$d = "esbuild" wide ascii
$e = "ajax" fullword
```

| Modifier | Meaning |
| --- | --- |
| `nocase` | Match ASCII letters in any case. |
| `wide` | Match UTF-16LE (each character followed by a zero byte). On its own it means wide only. |
| `ascii` | Match the plain form too. This is the default, and you only need it next to `wide`. |
| `fullword` | The match must not touch a letter, digit or underscore on either side. |

Escapes inside text strings: `\"`, `\\`, `\n`, `\t` and `\xNN`.

**Target:** `samples/jquery.min.js`, **result:** match.

```yara
rule Ajax_Fullword
{
  strings:
    $a = "ajax" fullword
  condition:
    $a
}
```

## Hex strings

```text
$mz   = { 4D 5A 90 00 }
$wild = { 7F 45 4C 46 ?? ?? 01 }
$jump = { 7F 45 4C 46 02 01 [10] 03 00 }
$range = { 7F 45 4C 46 02 01 [8-12] 03 00 }
```

- Bytes are two hex digits. Spaces are optional.
- `??` matches any byte.
- `[n]` skips exactly `n` bytes. `[n-m]` skips between `n` and `m`. `[n-]` means up to 4096.
- Half wildcards such as `4?` are accepted and treated as a full `??`.
- Alternations like `( 01 | 02 )` are not supported yet.

**Target:** `samples/ls-linux.elf`, **result:** match. A 64 bit little endian ELF whose `e_type`, 10 bytes after the class and data bytes, is `ET_DYN`:

```yara
rule ELF_64_LE_PIE : format
{
  meta:
    description = "64 bit little endian ELF with type ET_DYN"
    severity = "info"
  strings:
    $h = { 7F 45 4C 46 02 01 [10] 03 00 }
  condition:
    $h at 0
}
```

## Regex strings

```text
$v = /go1\.[0-9]{2}\.[0-9]+/
$p = /powershell.{0,40}-enc/ i
```

Regexes use JavaScript syntax and run over the file decoded as Latin-1, so offsets equal byte offsets. The `i` and `s` flags are supported. For speed, regex search covers the first 16 MB of a file.

**Target:** `esbuild.wasm` from `esbuild-wasm@0.24.0`, **result:** match.

```yara
rule Go_WASM : lang
{
  strings:
    $magic = { 00 61 73 6D 01 00 00 00 }
    $goos = /GOOS=js/
  condition:
    $magic at 0 and $goos
}
```

## Conditions

| Expression | True when |
| --- | --- |
| `$a` | `$a` matched at least once. |
| `not $a` | `$a` did not match. |
| `$a and $b`, `$a or $b` | Boolean logic. `and` binds tighter than `or`. Use parentheses to be clear. |
| `any of them` | At least one string matched. |
| `all of them` | Every string matched. |
| `2 of them` | At least two strings matched. |
| `1 of ($a, $b)` | At least one in the set matched. |
| `all of ($net*)` | Every string whose name starts with `$net` matched. |
| `#a > 5` | `$a` matched more than five times (counts stop at 1000). |
| `@a[1] == 0` | The first match of `$a` is at offset 0. `@a` alone means `@a[1]`. |
| `$a at 0` | `$a` has a match at exactly that offset. |
| `$a in (0..64)` | `$a` has a match starting between those offsets, inclusive. |
| `filesize < 200KB` | Compares the file size. `KB` and `MB` suffixes work, and so does hex like `0x400`. |
| `uint16(18) == 0xB7` | Reads a little endian integer at an offset. `uint8`, `uint16`, `uint32` (and `int` forms) are supported. |
| `uint32be(0) == 0x7F454C46` | The same, big endian. |
| `uint32(uint32(0x3C))` | Reads can nest, and the result can be used as an offset. |
| `filesize \ 1024` | Arithmetic: `+`, `-`, `*`, `\` (integer division), `&` and `\|`. |
| `true`, `false` | Constants. |

Comparison operators are `==`, `!=`, `<`, `<=`, `>` and `>=`.

**Target:** `esbuild.exe` from `@esbuild/win32-x64@0.24.0`, **result:** match. A real PE check: `MZ` at the start and the `PE\0\0` signature where `e_lfanew` points.

```yara
rule Is_PE : format
{
  meta:
    description = "MZ header with a PE signature at e_lfanew"
    severity = "info"
  strings:
    $mz = { 4D 5A }
  condition:
    $mz at 0 and uint32(uint32(0x3C)) == 0x00004550
}
```

**Target:** `samples/ls-linux.elf`, **result:** match. No strings at all, only integer reads. `0xB7` is `EM_AARCH64`.

```yara
rule ELF_AArch64
{
  condition:
    uint32be(0) == 0x7F454C46 and uint16(18) == 0xB7
}
```

**Target:** `samples/jquery.min.js`, **result:** match. Counts, offsets, size and sets together:

```yara
rule jQuery_Build : library
{
  meta:
    description = "A minified jQuery build with its banner at the start"
    severity = "info"
  strings:
    $banner = "/*! jQuery v"
    $name = "jQuery"
    $net1 = "XMLHttpRequest"
    $net2 = "onreadystatechange"
    $dom = "querySelectorAll"
  condition:
    $banner at 0 and #name > 5 and @name[2] < 1000
    and all of ($net*) and $dom
    and filesize > 80KB and filesize < 1MB
}
```

**Target:** `samples/jquery.min.js`, **result:** match. `N of (...)` with one string that is not there:

```yara
rule Two_Of_Three
{
  strings:
    $a = "XMLHttpRequest"
    $b = "getElementsByTagName"
    $c = "this_string_is_not_in_jquery"
  condition:
    2 of ($a, $b, $c)
}
```

**Target:** `samples/jquery.min.js`, **result:** no match. A rule that should not fire on a clean library:

```yara
rule Packed_With_UPX
{
  strings:
    $a = "UPX0"
    $b = "UPX1"
    $c = "UPX!"
  condition:
    2 of them
}
```

## A complete rule for a real binary

**Target:** `esbuild.exe` from `@esbuild/win32-x64@0.24.0`, **result:** match, with `$magic` at offset 9913344 and `$rt` at offset 7446911.

```yara
rule Go_Binary : lang
{
  meta:
    description = "Go build info and runtime strings"
    severity = "info"
  strings:
    $magic = { FF 20 47 6F 20 62 75 69 6C 64 69 6E 66 3A }
    $rt = "runtime.gopanic"
    $ver = /go1\.[0-9]{2}\.[0-9]+/
  condition:
    $magic and ($rt or $ver)
}
```

## The starter pack

These rules ship with RevLens and run on every file. You can read them in `packages/core/src/rules/starter.ts`.

| Rule | Tag | Severity | Looks for |
| --- | --- | --- | --- |
| `UPX_Packed` | packer | medium | two of `UPX0`, `UPX1`, `UPX!` |
| `Embedded_PE_Payload` | dropper | medium | a second DOS stub or MZ header inside the file |
| `Process_Injection_APIs` | injection | high | `VirtualAllocEx` and `WriteProcessMemory` with a thread or APC API |
| `Keylogger_APIs` | collection | medium | two keyboard hook or polling APIs |
| `Anti_Debug_Windows` | evasion | low | two debugger detection APIs |
| `Linux_Ptrace_AntiDebug` | evasion | low | `TracerPid` checks or `PTRACE_TRACEME` |
| `Reverse_Shell_Strings` | execution | high | common reverse shell command lines and encoded PowerShell |
| `Crypto_Constants` | crypto | info | the AES S-box or SHA-256 round constants |
| `Ransom_Note_Language` | impact | high | ransom note phrases |
| `Crypto_Miner` | impact | high | mining pool protocols and miner names |
| `JS_Eval_Decoded` | obfuscation | medium | `eval` or `new Function` of decoded or fetched strings |
| `NPM_Credential_Stealer` | supply_chain | high | credential file names plus `process.env` plus a network call |
| `Discord_Token_Grabber` | collection | high | Discord webhooks with token storage paths or token shapes |

## Differences from YARA

Supported here and in YARA: everything in the tables above.

Not supported yet:

- Modules (`import "pe"`, `pe.imphash()`, `math.entropy()`). Use the report fields instead: imphash is in `report.hardening.imphash`, entropy per section is in `report.sections`.
- `for` loops, `of` with a percentage.
- Hex alternations `( AA | BB )` and nibble wildcards as true nibbles.
- `xor`, `base64` and `private` string modifiers.
- Rule references inside conditions and `private` or `global` rule semantics.

Good to know:

- A string matches at most 1000 times. That cap keeps huge files fast.
- Hits are found on raw bytes, so a text string will match inside a compressed archive only if that member is stored uncompressed. RevLens analyzes archive members as child reports, and the rule pack runs on each of them too.
