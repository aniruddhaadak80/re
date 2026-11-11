# @revlens/desktop

Process, installed app and native UI reverse engineering for RevLens, on Linux, macOS and Windows.

- Process inspection: list processes; for one process get its executable, command line, parent and
  children, loaded modules and libraries with base addresses, open files, and TCP, UDP and Unix sockets.
- Process comparison: save two snapshots and see which modules, files, sockets and children came or went,
  plus memory and thread changes and a similarity score.
- App discovery: installed apps from Linux `.desktop` entries (XDG, Flatpak and Snap folders), macOS
  `.app` bundles (`Info.plist`, XML or binary) and the Windows uninstall registry keys (`reg query`).
  Electron apps are flagged with their `app.asar`, ready for `web_electron_audit` in `@revlens/webrt`.
- Native UI tree: the accessibility tree of a running app through AT-SPI (gdbus) on Linux, System Events
  (osascript JXA) on macOS and UIAutomation (PowerShell) on Windows: role, name, description, value,
  automation id and screen bounds, with parent links.

## Safety

Anything that reads another process or another app's UI needs `allowExecution: true` (or
`REVLENS_ALLOW_EXECUTION=1`). Inspecting the calling process itself does not. Every external command runs
through `execFile` with an argument array, no shell, a timeout and an output cap. Process ids are checked
as integers before they reach a command, and the one string that goes into a PowerShell script (the UI
tree app filter) is passed as a single-quoted literal with quotes doubled and control characters removed.
Environment variables of other processes are never read. Parsers cap sizes, counts and nesting and are
fuzzed with fast-check.

## API

Browser safe (`@revlens/desktop`): `parsePlist`, `parseBinaryPlist`, `parseXmlPlist`, `parseDesktopFile`,
`splitExec`, `desktopEntryToApp`, `infoPlistToApp`, `parseRegQuery`, `uninstallKeysToApps`,
`parseProcStatus`, `parseCmdline`, `parseProcMaps`, `parseProcNet`, `parseProcNetUnix`, `parseLsofF`,
`parsePs`, `parseWinProcesses`, `parseWinProcessDetail`, `parseGVariant`, `parseAccessibleRefs`,
`compareSnapshots`, `ANALYZERS`, `TOOLS`.

Node (`@revlens/desktop/node`): `listProcesses`, `snapshotProcess`, `compareProcessSnapshots`,
`listApps`, `inspectApp`, `defaultAppDirs`, `captureUiTree`, `TOOLS`, `CLI_COMMANDS`.

## Analyzers

- `desktop-entry`: `.desktop` files. App record under `report.meta.desktop.desktopEntry`, findings for
  shell launchers, download-and-run commands and autostart entries (ATT&CK T1547.013, T1105).
- `desktop-plist`: XML and binary plists. Parsed value under `report.meta.desktop.plist`, app summary for
  `Info.plist`, a finding when App Transport Security allows arbitrary loads.

## Tools

| Tool | What it does |
|---|---|
| desktop_process_list | processes with pid, parent, name, path, command line, user, threads, memory |
| desktop_process_inspect | one process: modules, open files, sockets, children; can save a snapshot file |
| desktop_process_compare | compare two snapshot files |
| desktop_apps_list | installed apps for this platform |
| desktop_app_inspect | one `.desktop`, `.app` or `Info.plist`, with executable resolution and Electron detection |
| desktop_ui_tree | native accessibility tree of a running app |
| desktop_plist_parse | parse a plist (browser safe) |
| desktop_entry_parse | parse a `.desktop` file (browser safe) |
| desktop_reg_uninstall_parse | parse `reg query` uninstall output (browser safe) |
| desktop_proc_parse | parse copied `/proc` text or `lsof -F` output (browser safe) |
| desktop_gvariant_parse | parse `gdbus call` output (browser safe) |
| desktop_snapshot_compare | compare two snapshots given as JSON text (browser safe) |

## CLI commands

```
revlens ps --allow-execution [--filter text]
revlens proc-inspect <pid> --allow-execution [--save snap.json]
revlens proc-compare <a.json> <b.json>
revlens apps [--filter text] [--hidden] [--resolve] [--dir path]
revlens app-inspect <file.desktop|App.app|Info.plist>
revlens ui-tree --allow-execution [--app name] [--pid N]
```

All print text by default and JSON with `--json`.

## How each platform is read

| | Linux | macOS | Windows |
|---|---|---|---|
| process list | `/proc/<pid>/status`, `cmdline`, `exe` | `ps -axo` | `Get-CimInstance Win32_Process` |
| modules | `/proc/<pid>/maps` | `lsof` txt entries plus `vmmap -w` images | `Get-Process` Modules |
| open files | `/proc/<pid>/fd` | `lsof -F` | not listed (needs Sysinternals handle.exe) |
| sockets | `/proc/<pid>/net/{tcp,tcp6,udp,udp6,unix}` joined by inode | `lsof -F` | `Get-NetTCPConnection`, `Get-NetUDPEndpoint` |
| apps | `.desktop` in XDG, Flatpak, Snap folders | `/Applications`, `~/Applications` Info.plist | `reg query ...\Uninstall /s` (HKLM, WOW6432Node, HKCU) |
| UI tree | AT-SPI over `gdbus` | System Events via `osascript -l JavaScript` | UIAutomation via PowerShell |

## Verified against

Run on Linux aarch64 (Debian 13) in the build sandbox:

- XML and binary plists written by Python `plistlib` decode to exactly the values `plistlib.loads` returns.
- The real `.desktop` files in `/usr/share/applications` give the same Name, Exec and Type as Python
  `configparser`.
- A live Node process holding a file, a TCP listener, a UDP socket and a Unix listener: the snapshot finds
  each one with the right port, address and state; its parent pid, name and command line match `ps`;
  every library `ldd` lists for the node binary is in the module list; and `lsof 4.99.4 -F` output parsed by
  `parseLsofF` gives the same library list, executable, file and sockets as `/proc`.
- Two snapshots taken before and after the process opens one more file and a TCP connection to itself
  show exactly that file and both ends of the connection as added.
- AT-SPI: with a real `dbus-daemon`, `at-spi2-registryd` 2.56 and Chromium 156 on the headless Ozone
  backend, `captureUiTree` returns the application, its frame, and the page's heading "Fixture heading",
  button "Press me" and entry "Search box", with parent links; the pid filter works through the bus
  daemon's `GetConnectionUnixProcessID`.

Not run here: the macOS (`ps`, `lsof`, `vmmap`, `osascript`) and Windows (PowerShell, `reg`) paths. Their
output parsers are tested on hand-written samples in the documented formats, but the live commands still
need a CI run on those systems.

## Limits

Lists are capped (500 processes and 20000 modules, files or sockets per call by default, paging with
offset and limit). UI trees default to 300 nodes and depth 8 (max 5000 and 64). AT-SPI costs three
`gdbus` calls per node, so large trees take seconds. Reading another user's processes needs the matching
OS permission; missing data is reported in `warnings`.
