# @revlens/desktop

Process, installed app and native UI reverse engineering for RevLens, on Linux, macOS and Windows.

- Process inspection: list processes; for one process get its executable, command line, parent and
  children, loaded modules and libraries with base addresses, open files, and TCP, UDP and Unix sockets.
- Process comparison: save two snapshots and see which modules, files, sockets and children came or went,
  plus memory and thread changes and a similarity score.
- App discovery: installed apps from Linux `.desktop` entries (XDG, Flatpak and Snap folders), macOS
  `.app` bundles (`Info.plist`, XML or binary) and the Windows uninstall registry keys (`reg query`).
  Electron apps are flagged with their `app.asar`, ready for `web_electron_audit` in `@revlens/webrt`.
- Native UI tree: the accessibility tree of a running app through AT-SPI on Linux (RevLens's own D-Bus
  client over one socket, with `gdbus` as a fallback), System Events (osascript JXA) on macOS and
  UIAutomation (PowerShell) on Windows: role, name, description, value, automation id and screen bounds,
  with parent links, and on Linux also states, actions, text and values.
- Build computer: an isolated desktop an agent drives (Linux: private Xvfb display, window manager,
  private D-Bus and AT-SPI bus), or the current display after explicit consent (X11, Wayland, macOS,
  Windows). Actions: move, click, double and right click, drag, type, key, scroll, wait, screenshot, cursor,
  windows, launch. Checkpoints save a screenshot, the UI tree, the window list and process snapshots with
  SHA-256 digests. Every action goes into a hash-chained audit log that `desktop_audit_verify` checks.
- Native UI action tracing and scenarios: accessibility events for a pid or app for a bounded time (AT-SPI
  signals, UIAutomation event handlers, or tree polling on macOS), with actions performed while listening
  and a before and after tree diff; scripted scenarios that find elements by role and name, click through
  the accessibility action or the pointer, type, press keys, wait and assert state, saving a tree and a
  screenshot per step; and UI tree comparison.
- Process capture: start a command or attach to a pid for a bounded time, sample modules, files, sockets,
  children, memory and threads, record syscalls with strace on Linux, and compare two captures.
- App state, export and tasks: where an installed app keeps its state (XDG folders, dconf, Flatpak and
  Snap data, macOS preference plists and containers, Windows AppData and HKCU registry, Electron userData
  with Local Storage keys read from LevelDB logs), a zip export with a manifest and secrets redacted by
  name, and task files whose checks are evaluated against typed views of the files and scored the same way
  as `x_eval_score` in `@revlens/extras`.

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

Also browser safe (round 3): D-Bus wire codec (`encodeMessage`, `decodeMessage`, `Variant`), UI model
(`findNode`, `findNodes`, `checkSelector`, `normalizeRole`, `decodeAtspiStates`, `compareUiTrees`,
`summarizeEvents`), `parseStrace`, `compareCaptures`, `readLevelLog`, `decodeLocalStorage`, typed views
(`viewOf`, `parseXml`, `parseKeyFile`, `resolvePointer`), redaction (`redactValue`, `redactLines`,
`isSecretFile`), tasks (`validateTask`, `runTask`, `toEvalTasks`, `scoreTaskAnswers`), `writeZip`,
`listZip`, `readZipEntry`, `decodeXwd`, `encodePng`, `pngInfo`, `diffImages`, `parseKeyCombo`.

Node (`@revlens/desktop/node`): `listProcesses`, `snapshotProcess`, `compareProcessSnapshots`,
`listApps`, `inspectApp`, `defaultAppDirs`, `captureUiTree`, `TOOLS`, `CLI_COMMANDS`, and from round 3
`startComputer`, `actOnComputer`, `checkpointComputer`, `closeComputer`, `listComputers`,
`verifyAuditLog`, `traceUi`, `runUiScenario`, `captureProcess`, `compareCaptureFiles`, `appState`,
`appExport`, `checkTaskFile`, `stateCandidates`, `Atspi`, `DBusClient`, and the input drivers
(`XdotoolDriver`, `YdotoolDriver`, `MacDriver`, `WindowsDriver`).

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
| desktop_computer_start | start an isolated or attached computer session (consent and allowExecution required) |
| desktop_computer_act | one action on a session; returns the result and its audit entry hash |
| desktop_computer_checkpoint | screenshot, UI tree, windows and process snapshots with a digest manifest |
| desktop_computer_close | stop everything the session started and seal the audit log |
| desktop_computer_list | open sessions |
| desktop_audit_verify | check an audit log's hash chain |
| desktop_ui_trace | accessibility events for a bounded time, with actions while listening and a tree diff |
| desktop_ui_scenario | scripted find, click, type, key, wait and assert steps with per-step evidence |
| desktop_ui_compare | diff two UI trees (browser safe) |
| desktop_process_capture | bounded capture of a command or pid, with strace on Linux |
| desktop_capture_compare | compare two captures (browser safe) |
| desktop_app_state | an app's state folders, files, registry, dconf and Electron Local Storage |
| desktop_app_export | zip of the state with a manifest, secrets withheld or masked |
| desktop_task_check | evaluate a task file against a home folder and a saved UI tree |
| desktop_task_validate | check a task file and turn its checks into eval tasks (browser safe) |
| desktop_task_score | score answers like `x_eval_score` (browser safe) |
| desktop_strace_parse | summarise strace output (browser safe) |
| desktop_leveldb_log | read a LevelDB `.log`, optionally as Chromium Local Storage (browser safe) |
| desktop_screenshot_info | PNG size, or XWD size and a pixel (browser safe) |

## CLI commands

```
revlens ps --allow-execution [--filter text]
revlens proc-inspect <pid> --allow-execution [--save snap.json]
revlens proc-compare <a.json> <b.json>
revlens apps [--filter text] [--hidden] [--resolve] [--dir path]
revlens app-inspect <file.desktop|App.app|Info.plist>
revlens ui-tree --allow-execution [--app name] [--pid N]
revlens ui-compare <a.json> <b.json> [--ignore bounds]
revlens ui-trace --allow-execution [--pid N] [--app name] [--duration ms] [--mode events|poll]
revlens ui-scenario <steps.json> --allow-execution [--pid N] [--app name] [--out dir]
revlens proc-capture --allow-execution [--duration ms] [--no-strace] [--out file] (--pid N | -- program args...)
revlens capture-compare <a.json> <b.json>
revlens app-state (<file.desktop|App.app> | --name N | --id ID | --bundle-id ID) [--home dir]
revlens app-export (<file.desktop|App.app> | --name N | --id ID | --bundle-id ID) --out state.zip [--no-redact]
revlens task-check <task.json> [--home dir] [--ui-tree tree.json]
revlens audit-verify <audit.jsonl>
revlens computer-run <script.json> --consent --allow-execution
```

`computer-run` takes `{"start": {...}, "steps": [{"act": {...}}, {"checkpoint": {...}}, {"trace": {...}},
{"scenario": [...]}]}` and runs it in one process, since a session lives as long as the process that
started it.

All print text by default and JSON with `--json`.

## How each platform is read

| | Linux | macOS | Windows |
|---|---|---|---|
| process list | `/proc/<pid>/status`, `cmdline`, `exe` | `ps -axo` | `Get-CimInstance Win32_Process` |
| modules | `/proc/<pid>/maps` | `lsof` txt entries plus `vmmap -w` images | `Get-Process` Modules |
| open files | `/proc/<pid>/fd` | `lsof -F` | not listed (needs Sysinternals handle.exe) |
| sockets | `/proc/<pid>/net/{tcp,tcp6,udp,udp6,unix}` joined by inode | `lsof -F` | `Get-NetTCPConnection`, `Get-NetUDPEndpoint` |
| apps | `.desktop` in XDG, Flatpak, Snap folders | `/Applications`, `~/Applications` Info.plist | `reg query ...\Uninstall /s` (HKLM, WOW6432Node, HKCU) |
| UI tree | AT-SPI over RevLens's D-Bus client (`gdbus` fallback) | System Events via `osascript -l JavaScript` | UIAutomation via PowerShell |
| computer input | `xdotool` (X11), `ydotool` (Wayland) | `cliclick` when installed, else CoreGraphics events from JXA, `System Events` keystroke | `SendInput` through an Add-Type helper |
| screenshot | `xwd -root` decoded and encoded to PNG in TS (`grim` on Wayland) | `screencapture -x` | `System.Drawing` CopyFromScreen |
| isolated display | `Xvfb -displayfd`, a window manager (matchbox, openbox, xfwm4, metacity, fluxbox, icewm, twm), private `dbus-daemon` and `at-spi2-registryd` | not available (attach only) | not available (attach only) |
| UI events | AT-SPI signals after `RegisterEvent` on the registry | tree polling and diffing | UIAutomation focus, structure, property, invoke and window handlers |
| process capture | `/proc` sampling plus `strace -f -tt -T` | `ps`, `lsof`, `pgrep` sampling | `Get-Process`, CIM sampling |
| app state | XDG config, data, state, cache, dotfolders, Flatpak, Snap, `dconf dump` | `~/Library` Preferences, Application Support, Containers, Caches, saved state | `%APPDATA%`, `%LOCALAPPDATA%`, `reg query HKCU\Software\...` |

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

Round 3, run in the same sandbox with Xvfb 21.1.16, xdotool 3.20160805, xwd, matchbox-window-manager,
dbus-daemon 1.16, at-spi2-registryd 2.56, Chromium 156 on the X11 Ozone backend and strace 6.13 (all from
Debian .deb files unpacked without root by `scripts/fetch-desktop-tools.py`):

- D-Bus: the client's `GetId` reply equals `gdbus call` against the same `dbus-daemon`, and its pid lookup
  returns the test's own pid.
- Screenshots: `xwd -root` of the session decoded by `decodeXwd` is byte-identical to ImageMagick's
  `convert xwd:- rgba:-`; our PNG decodes in Pillow to the same RGBA; the page's red square reads
  255,0,0 where the browser placed it.
- Input: a pointer click on the checkbox sets its AT-SPI `checked` state; typed text (including a leading
  dash) and ctrl+a, BackSpace arrive as the entry's AT-SPI text; the cursor reads back where it was
  moved; secret text never appears in the audit log, only its SHA-256.
- Checkpoints: every file's digest matches the manifest; the tree holds the page button; the process
  snapshot of Chromium lists libc.
- UI trace: an AT-SPI action on the button produces events and a tree diff whose status text changed to
  "Clicked N"; poll mode sees the same change.
- Scenario: accessibility click, wait, type, pointer click and asserts all pass on Chromium, a failing
  assert stops the rest, and each step's screenshot digest matches its file.
- Audit: the log verifies after close, an edited line is reported at its line number, and every process
  the session started is gone.
- Process capture: a Node program that reports what it did (marker file, TCP connection, child process,
  exit 7) is found in the samples and in the strace record; attaching to a running pid finds its file and
  listener.
- strace parser: calls and errors per syscall equal `strace -C`'s own summary for a real Python run.
- Typed views and tasks: values agree with Python `json`, `configparser`, `xml.etree`, `sqlite3`,
  `zipfile`, `gzip` and `plistlib`; the fixture task gives the result each check was built for, and
  `scoreAnswers` from `@revlens/extras` scores its answers to the same totals as `desktop_task_score`.
- App state and export: files, formats and SHA-256 match the fixture home; Python `zipfile` finds the
  export valid, with Cookies withheld and password, token and plist secrets masked. Real Chromium userData:
  Local Storage keys and values (including UTF-16) and a deleted key come back from the LevelDB log, and
  the token value is nowhere in the export.

Not run here: the macOS (`ps`, `lsof`, `vmmap`, `osascript`) and Windows (PowerShell, `reg`) paths. Their
output parsers are tested on hand-written samples in the documented formats, but the live commands still
need a CI run on those systems.

## Limits

Lists are capped (500 processes and 20000 modules, files or sockets per call by default, paging with
offset and limit). UI trees default to 300 nodes and depth 8 (max 5000 and 64). The built-in D-Bus client
uses one socket for the whole walk; the `gdbus` fallback costs three processes per node.
Computer sessions: at most 4 at once, closed after 30 minutes idle, and torn down when the host process
exits; isolated sessions need Linux. A UI trace lasts at most 120 s and keeps 50000 events; a process
capture lasts at most 10 minutes. macOS input needs Accessibility permission and screenshots need Screen
Recording permission; without them actions fail or are ignored by the system. strace attach needs ptrace
permission (`kernel.yama.ptrace_scope`). Local Storage is read from LevelDB `.log` files only; `.ldb`
tables need Snappy and are listed, not decoded. Task checks take no regular expressions.

## Round 3 compared with rea's desktop features

rea (morluto/rea, MIT) has a build computer that runs inside agentenv and Docker containers, native UI
observation and tracing through a macOS helper, process capture scenarios and desktop app state, export
and tasks. RevLens covers the same ground with these differences:

- The build computer needs no Docker or agentenv: an isolated session is a private Xvfb display on the
  host, and macOS and Windows desktops can be driven after explicit consent. Every action is in a hash
  chained audit log, and checkpoints carry digests.
- Native UI tracing and scenarios work on Linux (AT-SPI events), Windows (UIAutomation events) and macOS
  (polling), not only one platform, and UI trees from any backend can be diffed.
- Process capture adds syscalls from strace and a capture diff, and every parser runs in a browser worker
  on saved output.
- Task files use the same check kinds and pointer selectors as rea's desktop tasks and add `ui_element`
  checks on a saved UI tree; answers score the same way as `x_eval_score`. Reading another user's processes needs the matching
OS permission; missing data is reported in `warnings`.
