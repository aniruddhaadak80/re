# Packet capture playbook

Captures in pcap or pcapng format record network traffic. RevLens reads them without running
anything and without network access.

## Recognise
- `analyze_file` reports `pcap` or `pcapng`.

## First pass
1. `web_pcap_summary` for link types, time range, protocols, hosts and DNS names.
2. `web_pcap_flows` for TCP and UDP conversations with byte counts, and HTTP requests and TLS server names where visible.
3. `web_har_summary` when you have a browser HAR export instead of a capture.

## What to look for
- DNS names that look generated, beacons at a fixed interval, and plain text credentials.
- TLS server names that do not match the HTTP Host or the certificate.
- Large uploads to hosts the program should not talk to.

## Verify
- Cite the packet number and timestamp for each claim, and the flow 5 tuple.
