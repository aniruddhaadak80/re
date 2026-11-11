# samples/bridges fixtures

Every file here is original RevLens test material, MIT licensed, built in the RevLens sandbox from the
sources in `src/`. Nothing was downloaded from third parties. Tool versions used to build and record
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
