---
title: "Showcase: a packet capture and an app database"
description: Summarize a browser packet capture with TLS SNI and JA3, then read an SQLite database with a safe SELECT.
order: 5
---

# Showcase: a packet capture and an app database

`samples/webrt/chrome-34-google.pcap` is a capture of Chrome 34 opening Google. `samples/webrt/fixture.sqlite` is a small app database.

## 1. The capture

```console
$ revlens pcap-summary samples/webrt/chrome-34-google.pcap
pcap, 42 packets, 10886 bytes, 0.273953s, 1 flows
protocols: ipv4=42 tcp=42
  tls #4 sni=google.de ja3=a607f3a5c94c2ee592af1456f36c8367
```

The JA3 value matches the Salesforce JA3 reference for this capture.

## 2. Flows

```console
$ revlens pcap-flows samples/webrt/chrome-34-google.pcap
tcp 192.168.4.149:55881 -> 74.125.239.152:443 tls pkts 23/19 bytes 2750/8136
```


## 3. The database

```console
$ revlens sqlite-tables samples/webrt/fixture.sqlite
page size 1024, 60 pages, utf8
  users (300 rows): id INTEGER pk, name TEXT, email TEXT, score REAL, avatar BLOB
  events (1000 rows): id INTEGER pk, user_id INTEGER, kind TEXT, payload TEXT
  sqlite_sequence (1 rows): name, seq
  kv (3 rows, without rowid): k TEXT pk, v TEXT
  view active_users
```


```console
$ revlens sqlite-query samples/webrt/fixture.sqlite "SELECT * FROM users LIMIT 3"
id	name	email	score	avatar
1	user1	user1@example.com	1.5	null
2	user2	user2@example.com	3	null
3	user3	null	4.5	null
(3 rows)
```

SQLite itself never runs. RevLens reads the pages and runs one read only SELECT.
