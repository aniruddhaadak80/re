# samples/bridges fixtures

Every file here is original RevLens test material, MIT licensed, built in the RevLens sandbox from the
sources in `src/`, except `recorded/adb/`, which holds real Android device captures taken from
permissively licensed public repositories (listed below with commit, path and license). Tool versions used to build and record
them are listed so the values in the tests can be reproduced.

| File | SHA-256 | How it was made |
| --- | --- | --- |
| `crackme-aarch64.elf` | 739ea7f531bed6ffae645db6072ccb57c7cd911337dd42513beace148d9db1d3 | `gcc -O0 src/crackme.c` with GCC 14.2.0 (Debian 13), aarch64 PIE, not stripped. Used by radare2, Ghidra, objdump. |
| `crackme-aarch64-static.elf` | f2860bcbdbcc3e1ebd0fdbc82f1daa2395a70ae69d4a0a07e7f3ac29e5804f8b | `zig cc -target aarch64-linux-musl -static -O0 -fno-sanitize=all -fno-stack-protector src/crackme.c`, zig 0.14.1, then `llvm-strip --strip-debug`. Used by gdb and lldb (no dynamic loader, which traps under gVisor ptrace). |
| `crackme-x86_64-static.elf` | 1bbe59814bc311d14e084f6bb7659cead17d49df9c19e88411b4a17dda779e0f | Same command with `-target x86_64-linux-musl`. For gdb and lldb on x64 CI. |
| `hello.jar` | a34e824bed2365326beb9196d79c53d8e670bced6d130593507cd8dc358ce69f | `javac` (Temurin 21) of `src/java/Hello.java`, zipped with fixed timestamps. |
| `hello.dex` | 519ae8847aaa44b38573c37e352b4dc05cabd25e7cd2bf5d5e45a063556c37bc | `d8` from r8.jar on the class above, release mode (no debug info, so jadx names parameters `i`, `i2`). |
| `hello-dotnet.dll` | 63746b2e79c2b670b9e0721b456d88394d83d557df83bdb006ddcde4362ac6fa | `dotnet build -c Release` of `src/dotnet/hello.csproj` and `Program.cs`, .NET SDK 8.0.428. |
| `firmware-sample.bin` | b1b776105aec63e350d2746cdae3713700a28513b8b1fdaffcab56e4fccf5128 | 2117 bytes: header `RVLNFW01`, gzip stream at 0x100, zip holding `etc/passwd.sample` at 0x400 (end of central directory at 0x48c), 1x1 PNG at 0x800 (its zlib IDAT stream at 0x829). Padding is zero bytes. |

## recorded/

Real output captured from the tools on the fixtures above, used by `test/parsers.test.ts`:

- `r2-*.json`, `r2-pdc-add_numbers.txt`: radare2 6.2.6 with the r2ghidra 6.2.6 plugin, `-2 -q -N -e cfg.sandbox=true -c 'aa;<cmd>'` on `crackme-aarch64.elf`.
- `objdump-d.txt`, `objdump-h.txt`, `objdump-t.txt`: GNU objdump 2.44 (Debian 13) on `crackme-aarch64.elf`.
- `gdb-batch-static-aarch64.txt`: gdb 16.3 batch run of `crackme-aarch64-static.elf a` with breakpoints on add_numbers and check_password and the RevLens stop markers.
- `lldb-batch-static-aarch64.txt`: lldb 19.1.7 batch run of the same.
- `binwalk-v2.txt`: binwalk 2.4.3 on `firmware-sample.bin`.
- `frida-ps.json`, `frida-ls-devices.txt`: frida-tools 17.26.2 in the sandbox.
- `ilspy-l.txt`: ilspycmd 9.1.0.7988 `-l cisde hello-dotnet.dll`.
- `adb-devices-empty.txt`: adb 1.0.41 `devices -l` with no device attached.
- `gdb-mi-session-aarch64.txt`: gdb 16.3 `--interpreter=mi3` session on `crackme-aarch64-static.elf hunter2` (break, run, info registers pc, bt, an unknown command, continue, exit), used by `test/sessions.test.ts`.
- `cutter/windows-release-v2.5.0-toplevel.txt`: the top level file names of the official `Cutter-v2.5.0-Windows-x86_64.zip` (github.com/rizinorg/cutter releases), read from the zip central directory with HTTP range requests. Only names, no Cutter files. Used by `test/cutter.test.ts` to rebuild the install layout.

## recorded/adb/

Android device output. The sandbox has adb 1.0.41 but no device or emulator, so the device side
captures come from public repositories under MIT or Apache-2.0. Files are copied byte for byte
unless marked as an excerpt (a line range of the original).

| File | Command | Source (commit, path) | License |
| --- | --- | --- | --- |
| `dumpsys-package-buzzkill-api35.txt` | `dumpsys package com.samruston.buzzkill`, API 35 emulator | github.com/SysAdminDoc/NoNo @ 7120dd6e716238e8b8dc3df5d15a76bcbb71b0a1, `app-audit/evidence/package/dumpsys-package-20260801-130512.txt` | MIT |
| `dumpsys-package-a2dp-api24.txt` | `dumpsys package a2dp.Vol` (DroidBot run) | github.com/luyangliuable/usability-accessibility-testing-app @ b99e3e1a66b92db0d2998725c8ba25ed78fe7c45, `seed_data/data/28f666de-9a79-4a03-ac74-da77acf5924a/gifdroid/dumpsys_package_a2dp.Vol.txt` | Apache-2.0 |
| `getprop-atv28.txt` | `getprop`, Android TV API 28 emulator (serials redacted by the source) | github.com/udhaykumarbala/cleanyourtv-app @ 03ad20ebec68284a362b9d90690876c18e212286, `fixtures/conformance/emu-atv28-2026-10-20/getprop.txt` | MIT |
| `getprop-mitv.txt` | `getprop`, Xiaomi Mi TV | same repo, `fixtures/conformance/mitv-axso0-2026-10-18/getprop.txt` | MIT |
| `settings-list-global-atv28.txt` | `settings list global` | same repo, `fixtures/conformance/emu-atv28-2026-10-20/settings-global.txt` | MIT |
| `resolve-activity-home-atv28.txt` | `cmd package resolve-activity --brief` for HOME | same repo, `.../emu-atv28-2026-10-20/home-activity.txt` | MIT |
| `pm-list-packages-f-atv28.txt` | `pm list packages -f` | same repo, `.../emu-atv28-2026-10-20/packages-all.txt` | MIT |
| `pm-path-gms-atv28.txt` | `pm path com.google.android.gms` | same repo, `.../emu-atv28-2026-10-20/gms-path.txt` | MIT |
| `ps-A-galaxy-a30s.txt` | `ps -A` then `top` on a Samsung Galaxy A30s | github.com/luisfvmartins/clean-my-android @ 7929a7e8c8b0e4f035a7951b8262cfa1ac34d671, `reports/samsung/galaxy-a30s/before/processes.txt` | MIT |
| `wm-size-density-tv.txt` | `wm size`, `wm density` (excerpt, lines 1-2) | github.com/ArpitKadam/android-device-debloater @ 7c1425aa5592712056c78786722eb18a9ea113d9, `SmartTV/backup/display_storage_mem.txt` | MIT |
| `am-start-W.txt` | `am start -W -n ...` | github.com/Eslamasabry/opencode-mobile-next @ 4f10364f29346e43dafb8de9eee7ce0307223189, `docs/qa/issue-87-proof-2026-09-25/p1-runs/cold-1/am_start.txt` | MIT |
| `install-push.txt` | `adb install` and `adb push` host output (excerpt, lines 411-416) | github.com/Lord1Egypt/AndroidThothTerm @ f79fcc7f73099112a8b3e1a1a2ea9ecfc3e68451, `docs/garden/closure/device-evidence/extractor-term-ubuntu.txt` | Apache-2.0 |
| `pull.txt` | `adb pull` host output (excerpt, line 24) | github.com/filipef101/c-sharp-native @ 564ba6bbc89f9ff7e32228c6fd3de46f5cc20e31, `evidence/hot-reload-edits.log` | MIT |
| `forward-list-empty.txt` | `adb forward --list`, no rules | recorded in the RevLens sandbox, adb 1.0.41 | MIT |
| `no-device-error.txt` | `adb shell getprop` with no device | recorded in the RevLens sandbox, adb 1.0.41 | MIT |
| `adb-version.txt` | `adb version` | recorded in the RevLens sandbox | MIT |
