# Playbooks

A playbook is a short, ordered plan for one kind of file. Each one says how to recognise the format,
which RevLens tools to call first, what to look for, which external bridges help when they are
installed, and how to check a claim before you report it.

The MCP server serves these pages through the `guidance`, `search_guidance` and
`read_guidance_section` tools, and the `guided_workflows` tool turns them into step lists with your
own arguments filled in.

| Format | Playbook |
| --- | --- |
| Linux and other ELF binaries | [elf.md](elf.md) |
| Windows PE executables and DLLs | [pe.md](pe.md) |
| Apple Mach-O and fat binaries | [macho.md](macho.md) |
| Android APK, AAB, DEX | [apk.md](apk.md) |
| iOS IPA | [ipa.md](ipa.md) |
| .NET assemblies and single file bundles | [dotnet.md](dotnet.md) |
| Python pyc, PyInstaller and frozen apps | [python.md](python.md) |
| JavaScript bundles and source maps | [js-bundle.md](js-bundle.md) |
| Electron apps and ASAR archives | [electron.md](electron.md) |
| Firmware images | [firmware.md](firmware.md) |
| Packet captures (pcap, pcapng) | [pcap.md](pcap.md) |
