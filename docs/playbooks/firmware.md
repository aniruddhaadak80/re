# Firmware playbook

Firmware images hold boot loaders, kernels, file systems and configuration, often wrapped in vendor
headers and compressed.

## Recognise
- `x_firmware_scan` looks for known signatures (uImage, FIT, TRX, squashfs, cramfs, JFFS2, UBI, gzip, xz, LZMA, device trees) at every offset.
- `x_firmware_parse` decodes a known container header.
- `analyze_file` reports Intel HEX, S-records, UF2 and ESP images directly.

## First pass
1. `x_firmware_scan` for a map of the image with offsets.
2. `x_firmware_parse` on each header found, then `x_container` to list embedded archives.
3. `get_strings` with `tag: url`, `tag: path` and `contains: passw` for credentials and update servers.
4. `x_address_map` when you know the load address, so offsets and addresses line up.

## Code
1. Extracted ELF programs follow the ELF playbook.
2. Bare metal code has no headers. Use `disasm_at` with the load address and architecture.

## Bridges that help
- binwalk (`bridge_binwalk`) for extraction of file systems RevLens only reports.

## Verify
- Cite the image offset for each part. Entropy from `get_sections` or the scan shows compressed or encrypted areas.
