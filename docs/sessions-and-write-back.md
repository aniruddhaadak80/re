---
title: Sessions and names write-back
description: Keep radare2, rizin, gdb, lldb and Frida running between calls with session ids and guards, and move function names, signatures, comments, labels and types between Ghidra, IDA and radare2 with one JSON format.
order: 25.4
---

# Sessions and names write-back

Part of `@revlens/bridges`. One shot bridge calls start a tool, ask one thing and exit. Sessions keep the tool alive so an agent can analyze once, ask many small questions, rename things and step a debugger. Write-back puts what the agent learned back into the project files of the tools you use.

## Sessions

| Tools | What they do |
|---|---|
| `bridge_r2_session_open`, `bridge_r2_session_cmd` | radare2 or rizin, static analysis only, sandbox switched on after loading |
| `bridge_gdb_session_open`, `bridge_gdb_session_cmd` | gdb over MI: breakpoints, stepping, registers, memory |
| `bridge_lldb_session_open`, `bridge_lldb_session_cmd` | lldb with the same idea |
| `bridge_frida_session_attach`, `_load`, `_post`, `_collect`, `_unload`, `_resume` | attach or spawn, load a template or script, post messages, collect events |
| `bridge_session_list`, `bridge_session_close` | list open sessions, close one |

How sessions behave:

- Each one has an id such as `gdb-3f9a1c0d2b7e`, an idle timeout (15 minutes by default, `REVLENS_SESSION_IDLE_MS`) and counts against a cap (8 by default, `REVLENS_MAX_SESSIONS`, at most 64).
- Calls on one session are queued, never interleaved. If gdb does not answer in time, the program is interrupted; radare2 and lldb sessions are ended instead because they cannot resync.
- When the MCP server exits, every session process group is killed, and each tool also quits when its stdin closes, so nothing outlives a crashed server.
- The debugged program never shares the debugger's command channel. Its output comes back as `programOutput`.
- Command guards refuse host escapes: in r2 `!`, backticks, pipes, redirects, scripts, `o`, `P`, `w` and sandbox changes; in gdb `shell`, `pipe`, `python`, `source`, `dump`, `set logging`, `file`, `attach`, `target` and similar; in lldb `platform shell`, `script`, `command`, `target` and hook command lists. Abbreviations are caught too.
- Starting a debugger or Frida needs `allowExecution`. Sessions live inside the process that opened them, so separate `revlens` CLI runs do not share them.

## Names write-back

One JSON shape, `revlens/names@1`, carries names between tools:

```json
{ "schema": "revlens/names@1", "imageBase": "0x0", "addressing": "va",
  "functions": [{ "address": "0x848", "name": "verify_secret", "signature": "int verify_secret(char *input)" }],
  "comments": [{ "address": "0x868", "text": "length check", "kind": "eol" }],
  "labels": [{ "address": "0xa08", "name": "g_secret" }],
  "types": [{ "name": "rl_pair", "c": "struct rl_pair { int a; char *b; };" }] }
```

| Tool | Apply | Export |
|---|---|---|
| Ghidra (headless) | `bridge_ghidra_apply_names` | `bridge_ghidra_export_names` |
| IDA (idat) | `bridge_ida_apply_names` | `bridge_ida_export_names` |
| radare2 and rizin | `bridge_r2_apply_names` | `bridge_r2_export_names` |

Addresses are moved with `address - imageBase + toolImageBase`, so a Ghidra export (PIE loaded at 0x100000) applies cleanly to radare2 (base 0) and back. Every value is checked before anything runs: names, one line C signatures, comments and type text without quotes or preprocessor lines.

```sh
revlens bridge ghidra_apply_names app.elf --names-path names.json
revlens bridge r2_export_names app.elf --out-path names.json
```

## How it was checked

radare2 6.2.6 keeps a rename across calls with the same addresses as a one shot run; gdb 16.3 over MI stops at a breakpoint, prints a local and is interrupted on timeout; lldb 19.1.7 waits for a breakpoint stop; a Frida 17.26.2 session round trips a post and send. Ghidra 12.2 applies names, a signature, comments, a label and a type, then decompiles `main` with the new names, and its export maps back onto radare2. The IDA scripts are checked against stub IDA modules that record each call, not a real IDA.

## Limits

- radare2 debug sessions are not offered; use the gdb or lldb sessions.
- Frida spawn needs ptrace and a working injector; attach works in more places.
- Cutter's window is not driven. RevLens writes rizin projects Cutter can open.
- Sessions do not survive a restart of the MCP server.
