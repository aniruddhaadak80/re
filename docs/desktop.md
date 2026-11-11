---
title: Desktop apps and processes
description: List and inspect running processes, compare process snapshots, find installed apps and Electron apps, and read the native accessibility tree on Linux, macOS and Windows with @revlens/desktop.
order: 25.2
---

# Desktop apps and processes

`@revlens/desktop` looks at software while it is installed and running on your machine. It lists processes and what they hold open, saves snapshots you can compare, finds installed apps, and reads the accessibility tree of a running app. It works on Linux, macOS and Windows and needs no native modules.

## Consent first

Reading another process or another app's UI needs `allowExecution: true` in the tool call, `--allow-execution` on the CLI, or `REVLENS_ALLOW_EXECUTION=1`. Inspecting the calling process itself does not. Environment variables of other processes are never read.

Every system command runs through `execFile` with an argument array, no shell, a timeout and an output cap. Process ids are checked as integers before they reach a command.

## Processes

```sh
revlens ps --allow-execution --filter node
revlens proc-inspect 4242 --allow-execution --save before.json
# do something in the app
revlens proc-inspect 4242 --allow-execution --save after.json
revlens proc-compare before.json after.json
```

`proc-inspect` gives the executable, command line, parent and children, loaded modules with base addresses, open files, and TCP, UDP and Unix sockets. `proc-compare` shows which modules, files, sockets and children came or went, memory and thread changes, and a similarity score.

| | Linux | macOS | Windows |
|---|---|---|---|
| process list | `/proc/<pid>/status`, `cmdline`, `exe` | `ps -axo` | `Get-CimInstance Win32_Process` |
| modules | `/proc/<pid>/maps` | `lsof` plus `vmmap -w` | `Get-Process` Modules |
| open files | `/proc/<pid>/fd` | `lsof -F` | not listed |
| sockets | `/proc/<pid>/net/*` joined by inode | `lsof -F` | `Get-NetTCPConnection`, `Get-NetUDPEndpoint` |

## Installed apps

```sh
revlens apps --filter slack --resolve
revlens app-inspect /Applications/Slack.app
```

Apps come from Linux `.desktop` entries (XDG, Flatpak and Snap folders), macOS `.app` bundles (XML or binary `Info.plist`) and the Windows uninstall registry keys. Electron apps are flagged with the path of their `app.asar`, ready for `web_electron_audit` (see [JavaScript and Electron](javascript-and-electron.md)).

## Native UI tree

```sh
revlens ui-tree --allow-execution --app "Text Editor"
```

The tree comes from AT-SPI over `gdbus` on Linux, System Events (JXA) on macOS and UIAutomation through PowerShell on Windows. Each node has its role, name, description, value, automation id, screen bounds and a parent link. Trees default to 300 nodes and depth 8.

## Tools

| Tool | What it does |
|---|---|
| `desktop_process_list` | processes with pid, parent, name, path, command line, user, threads, memory |
| `desktop_process_inspect` | one process: modules, open files, sockets, children; can save a snapshot |
| `desktop_process_compare` | compare two snapshot files |
| `desktop_apps_list` | installed apps for this platform |
| `desktop_app_inspect` | one `.desktop`, `.app` or `Info.plist`, with Electron detection |
| `desktop_ui_tree` | native accessibility tree of a running app |
| `desktop_plist_parse`, `desktop_entry_parse`, `desktop_reg_uninstall_parse`, `desktop_proc_parse`, `desktop_gvariant_parse`, `desktop_snapshot_compare` | parsers for copied text and files, safe in the browser |

Two analyzers also run inside `revlens analyze`: `desktop-entry` flags shell launchers, download and run commands and autostart entries in `.desktop` files, and `desktop-plist` flags App Transport Security exceptions in `Info.plist`.

## How it was checked

On Linux, plists written by Python `plistlib` decode to the same values, real `.desktop` files match `configparser`, and a live Node process with a file, TCP, UDP and Unix sockets shows each one with the right port and state, with the module list matching `ldd` and `lsof -F`. The AT-SPI path was run against a real `at-spi2-registryd` and Chromium. The macOS and Windows parsers are tested on output in the documented formats, and the package tests run on the macOS and Windows CI runners.

## Limits

- Windows does not list open files (that needs Sysinternals `handle.exe`).
- AT-SPI costs three `gdbus` calls per node, so big trees take seconds.
- Reading another user's processes needs the matching OS permission; what is missing is reported in `warnings`.
- UI actions are not traced or replayed yet; the tree is read only.
