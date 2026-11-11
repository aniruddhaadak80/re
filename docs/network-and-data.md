---
title: Network captures and data files
description: Summarize PCAP and pcapng captures with DNS, HTTP, TLS SNI and JA3, list flows, read SQLite databases with a safe SELECT engine, and review HAR logs.
order: 24
---

# Network captures and data files

Also part of `@revlens/webrt`. Everything here is pure TypeScript. SQLite itself is never run. Try it on the [network page](https://aniruddhaadak80.github.io/re/labs/network) and the [SQLite page](https://aniruddhaadak80.github.io/re/labs/sqlite).

## Packet captures

PCAP and pcapng with Ethernet, VLAN, Linux SLL and SLL2, null and raw IP links. You get:

- IPv4, IPv6, TCP and UDP flows with per direction counts.
- DNS queries and answers over UDP and TCP.
- HTTP/1.x requests and responses.
- TLS ClientHello SNI, ALPN and JA3, ServerHello JA3S.
- Summary statistics per protocol and host.

## SQLite

A page reader for b-trees, overflow pages, records and WITHOUT ROWID tables, plus a read only SELECT engine. You get the schema, row counts, sample rows and the result of one SELECT with a row cap.

## HAR

Hosts with third party marking, API endpoint patterns, redirects, auth header schemes and cookie names (values are never returned), missing security headers, mixed content, WebSockets, and endpoints found in captured scripts.

## CLI

```
revlens pcap-summary capture.pcap
revlens pcap-flows capture.pcapng
revlens sqlite-tables app.db
revlens sqlite-query app.db "SELECT name, email FROM users ORDER BY name LIMIT 20"
revlens har-summary session.har
```

## MCP tools

`web_pcap_summary`, `web_pcap_flows`, `web_sqlite_tables`, `web_sqlite_query`, `web_har_summary`.

## Limits

- TCP reassembly keeps the first 64 KB per direction and stops at the first gap. HTTP/2, QUIC and encrypted TLS records are not decoded.
- SQLite: no WAL merge, no recovery of deleted rows. SELECT supports one table, one ORDER BY column and no joins.

## How it was checked

tcpdump output for DNS, the Salesforce JA3 reference for fingerprints, dpkt for SNI and packet counts, Python `sqlite3` for schemas, counts and query results, real Playwright HAR files for redirects.
