# DPI Engine - Deep Packet Inspection System (Python Edition)

This document explains **everything** about this project - from basic networking concepts to the complete Python package architecture. After reading this, you should understand exactly how packets flow through the system without needing to read the code.

---

## Table of Contents

1. [What is DPI?](#1-what-is-dpi)
2. [Networking Background](#2-networking-background)
3. [Project Overview](#3-project-overview)
4. [File Structure](#4-file-structure)
5. [The Journey of a Packet (Simple Version)](#5-the-journey-of-a-packet-simple-version)
6. [The Journey of a Packet (Multi-threaded Version)](#6-the-journey-of-a-packet-multi-threaded-version)
7. [Deep Dive: Each Component](#7-deep-dive-each-component)
8. [How SNI Extraction Works](#8-how-sni-extraction-works)
9. [How Blocking Works](#9-how-blocking-works)
10. [Installation and Running](#10-installation-and-running)
11. [Understanding the Output](#11-understanding-the-output)
12. [Extending the Project](#12-extending-the-project)

---

## 1. What is DPI?

**Deep Packet Inspection (DPI)** is a technology used to examine the contents of network packets as they pass through a checkpoint. Unlike simple firewalls that only look at packet headers (source/destination IP), DPI looks *inside* the packet payload.

### Real-World Uses:
- **ISPs**: Throttle or block certain applications (e.g., BitTorrent)
- **Enterprises**: Block social media on office networks
- **Parental Controls**: Block inappropriate websites
- **Security**: Detect malware or intrusion attempts

### What Our DPI Engine Does:
```
User Traffic (PCAP) → [DPI Engine] → Filtered Traffic (PCAP)
                           ↓
                    - Identifies apps (YouTube, Facebook, etc.)
                    - Blocks based on rules
                    - Generates reports
```

---

## 2. Networking Background

### The Network Stack (Layers)

When you visit a website, data travels through multiple "layers":

```
┌─────────────────────────────────────────────────────────┐
│ Layer 7: Application    │ HTTP, TLS, DNS               │
├─────────────────────────────────────────────────────────┤
│ Layer 4: Transport      │ TCP (reliable), UDP (fast)   │
├─────────────────────────────────────────────────────────┤
│ Layer 3: Network        │ IP addresses (routing)       │
├─────────────────────────────────────────────────────────┤
│ Layer 2: Data Link      │ MAC addresses (local network)│
└─────────────────────────────────────────────────────────┘
```

### A Packet's Structure

Every network packet is like a **Russian nesting doll** - headers wrapped inside headers:

```
┌──────────────────────────────────────────────────────────────────┐
│ Ethernet Header (14 bytes)                                       │
│ ┌──────────────────────────────────────────────────────────────┐ │
│ │ IP Header (20 bytes)                                         │ │
│ │ ┌──────────────────────────────────────────────────────────┐ │ │
│ │ │ TCP Header (20 bytes)                                    │ │ │
│ │ │ ┌──────────────────────────────────────────────────────┐ │ │ │
│ │ │ │ Payload (Application Data)                           │ │ │ │
│ │ │ │ e.g., TLS Client Hello with SNI                      │ │ │ │
│ │ │ │ └──────────────────────────────────────────────────────┘ │ │ │
│ │ │ └──────────────────────────────────────────────────────────┘ │ │
│ │ └──────────────────────────────────────────────────────────┘ │ │
│ └──────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

### The Five-Tuple

A **connection** (or "flow") is uniquely identified by 5 values:

| Field | Example | Purpose |
|-------|---------|---------|
| Source IP | 192.168.1.100 | Who is sending |
| Destination IP | 172.217.14.206 | Where it's going |
| Source Port | 54321 | Sender's application identifier |
| Destination Port | 443 | Service being accessed (443 = HTTPS) |
| Protocol | TCP (6) | TCP or UDP |

**Why is this important?** 
- All packets with the same 5-tuple belong to the same connection
- If we block one packet of a connection, we block all of them
- This is how we track conversations between computers

### What is SNI?

**Server Name Indication (SNI)** is part of the TLS/HTTPS handshake. When you visit `https://www.youtube.com`:

1. Your browser sends a "Client Hello" message
2. This message includes the domain name in **plaintext** (not encrypted yet!)
3. The server uses this to know which certificate to send

```
TLS Client Hello:
├── Version: TLS 1.2
├── Random: [32 bytes]
├── Cipher Suites: [list]
└── Extensions:
    └── SNI Extension:
        └── Server Name: "www.youtube.com"  ← We extract THIS!
```

**This is the key to DPI**: Even though HTTPS is encrypted, the domain name is visible in the first handshake packet!

---

## 3. Project Overview

### What This Rebuilt Project Does
The project has been rebuilt in clean, production-ready Python 3.10+ with **zero third-party dependencies** for core packet decoding. It reads standard binary PCAPs, decodes them at the byte level, routes them through a consistent-hashing multi-threaded queue pipeline, extracts hostnames, runs rule checking, and outputs a filtered PCAP.

### Three Modes of Operation

| Mode | Command Flag | Use Case |
|------|--------------|----------|
| Multi-threaded | `--mode mt` | High-performance, parses using multiple Load Balancers & Fast Paths. |
| Simple | `--mode simple` | Stateful single-threaded connection tracker. |
| Print | `--mode print` | Dumps pretty-printed network packet header trees. |

---

## 4. File Structure

```
my_packet_analyzer/
├── README.md                 # Updated user documentation (this file)
├── requirements.txt          # Python dependencies (none strictly required)
├── pyproject.toml            # Packaging configuration
├── .gitignore                # Purged cache and output folders list
├── generate_test_pcap.py      # Creates mock test pcap traffic
├── test_dpi.pcap              # Freshly generated binary pcap sample
│
├── my_packet_analyzer/       # Rebuilt Python core package
│   ├── main.py               # Unified CLI entry point
│   ├── core/
│   │   ├── engine.py         # MT and Simple engine orchestrators
│   │   ├── types.py          # Enums, dataclasses, SNI mapping helper
│   │   └── queue.py          # Bounded ThreadSafeQueue implementation
│   ├── capture/
│   │   └── pcap.py           # Struct-based binary PcapReader and PcapWriter
│   ├── parser/
│   │   └── protocols.py      # Layer 2/3/4 headers decoding (MAC, IP, Port, Flag)
│   ├── dpi/
│   │   └── extractor.py      # SNI, HTTP Host, DNS, QUIC hostname inspects
│   ├── rules/
│   │   └── manager.py        # Rules manager with config serialization
│   ├── tracker/
│   │   └── flow.py           # Stateful connection maps and LRU flow eviction
│   └── utils/
│       └── helpers.py        # Logging, formatters, and IP/MAC conversions
│
├── tests/                    # Automated testing suite
│   ├── test_parser.py        # Decoders validation
│   ├── test_extractor.py     # DPI extraction verification
│   └── test_rules.py         # Manager matching validations
```

---

## 5. The Journey of a Packet (Simple Version)

Trace a packet through `main.py --mode simple`:

1. **Read PCAP File**: `PcapReader` opens the file, reads the 24-byte global header, and automatically matches endianness.
2. **Read Packets**: Read packet headers (16 bytes) and binary payload lengths iteratively.
3. **Parse Protocols**: `PacketParser.parse` decodes:
   - Ethernet (MACs, EtherType)
   - IPv4 (IP strings, Protocol, TTL)
   - TCP (Ports, Seq/Ack, Flags) or UDP (Ports)
4. **Identify Flow**: Match the packet against the `FiveTuple` (native or reverse) inside the `ConnectionTracker`.
5. **DPI Extraction**: Extract SNI from TLS Client Hello (443), Host headers from HTTP (80), or Queries from DNS (53). Map domain to `AppType`.
6. **Evaluate Rules**: Verify IP, Port, AppType, and Domain substring matches via the `RuleManager`.
7. **Forward/Drop**: Write allowed packets to the output PCAP; drop blocked packets.

---

## 6. The Journey of a Packet (Multi-threaded Version)

The multi-threaded engine (`--mode mt`) adds structured producer-consumer concurrency:

```
                    ┌─────────────────┐
                    │  Reader Thread  │
                    │  (reads PCAP)   │
                    └────────┬────────┘
                             │
               ┌──────────────┴──────────────┐
               │    hash(5-tuple) % num_lbs  │
               ▼                             ▼
    ┌─────────────────┐           ┌─────────────────┐
    │  LB0 Thread     │           │  LB1 Thread     │
    │  (Load Balancer)│           │  (Load Balancer)│
    └────────┬────────┘           └────────┬────────┘
             │                             │
       ┌──────┴──────┐               ┌──────┴──────┐
       │hash % 2     │               │hash % 2     │
       ▼             ▼               ▼             ▼
┌──────────┐ ┌──────────┐   ┌──────────┐ ┌──────────┐
│FP0 Thread│ │FP1 Thread│   │FP2 Thread│ │FP3 Thread│
│(Fast Path)│ │(Fast Path)│   │(Fast Path)│ │(Fast Path)│
└─────┬────┘ └─────┬────┘   └─────┬────┘ └─────┬────┘
       │            │              │            │
       └────────────┴──────────────┴────────────┘
                           │
                           ▼
               ┌───────────────────────┐
               │   Output Queue        │
               └───────────┬───────────┘
                           │
                           ▼
               ┌───────────────────────┐
               │  Output Writer Thread │
               │  (writes to PCAP)     │
               └───────────────────────┘
```

1. **Reader Thread**: Parses basic offsets, generates `PacketJob`, hashes the `FiveTuple`, and pushes it to an LB input queue.
2. **Load Balancer**: Consumes jobs, applies second-level hashing, and forwards them to a dedicated Fast Path.
3. **Fast Path**: Resolves the connection state, performs DPI classification, evaluates blocking, and pushes allowed packets to the output queue.
4. **Writer Thread**: Consumes the output queue and writes packets to the output PCAP file.

---

## 7. Deep Dive: Each Component

### `capture/pcap.py`
Reads and writes binary PCAPs. Employs Python `struct` to unpack formats. Endianness is handled automatically by matching the magic number and assigning `<` (little-endian) or `>` (big-endian) to format strings.

### `parser/protocols.py`
Unpacks layer 2/3/4 protocol headers. Converts source and destination IPs directly from binary arrays into standard string layouts without duplicate parsing functions.

### `dpi/extractor.py`
Inspects TCP payloads. The TLS engine walks the handshake body, sessions, and compression structures to parse the exact extension fields matching the SNI type `0x0000`. The QUIC parser runs heuristic scans to match TLS cryto payloads in initial UDP datagrams.

### `rules/manager.py`
Verifies rules against connections. Supports wildcard matching (e.g. `*.google.com` blocks all subdomains and bare domain matches). Rule managers read and write local configurations dynamically using structured text blocks.

---

## 8. How SNI Extraction Works

We scan the record layer for Content Type `0x16` (Handshake) and handshake type `0x01` (Client Hello). The parser then skips the handshake metadata:
- Random bytes (32 bytes)
- Session ID (variable length)
- Cipher Suites (variable length)
- Compression methods (variable length)

Once at the Extensions offset, it iterates over all extension blocks. If type is `0x0000` (SNI), it parses the list structure, reads the hostname value, and maps it to `AppType`.

---

## 9. How Blocking Works

We check rules at the **flow** level. The first three packets of a connection (TCP SYN, SYN-ACK, ACK handshake) are forwarded because there is no payload/SNI to analyze. Once the Client Hello is parsed, the flow is classified. If it matches a blocked app/domain, the Client Hello packet is dropped, the connection is marked `BLOCKED`, and all subsequent data packets are instantly dropped.

---

## 10. Installation and Running

### Requirements
- Python 3.10+ (tested up to Python 3.14)
- Zero external libraries required for core execution.

### CLI Usage

**1. Print Mode (packet dumps)**:
```bash
python -m my_packet_analyzer.main test_dpi.pcap --mode print --max-packets 10
```

**2. Stateful Single-Threaded Mode**:
```bash
python -m my_packet_analyzer.main test_dpi.pcap output_simple.pcap --mode simple --block-app YouTube --block-ip 192.168.1.50
```

**3. Concurrent Multi-threaded Mode**:
```bash
python -m my_packet_analyzer.main test_dpi.pcap output_mt.pcap --mode mt --block-app YouTube --block-ip 192.168.1.50 --lbs 2 --fps 2
```

### Running Automated Unit Tests
```bash
python -m unittest discover -s tests
```

---

## 11. Understanding the Output

The engine prints a detailed aligned ASCII table on completion:

```
╔══════════════════════════════════════════════════════════════╗
║                      PROCESSING REPORT                        ║
╠══════════════════════════════════════════════════════════════╣
║ Total Packets:      77                                       ║
║ Total Bytes:        5738                                     ║
║ TCP Packets:        73                                       ║
║ UDP Packets:        4                                        ║
╠══════════════════════════════════════════════════════════════╣
║ Forwarded:          70                                       ║
║ Dropped:            7                                        ║
╠══════════════════════════════════════════════════════════════╣
║ THREAD STATISTICS                                             ║
║   LB0 dispatched:   42                                       ║
║   LB1 dispatched:   35                                       ║
║   FP0 processed:    42                                       ║
║   FP1 processed:    0                                        ║
║   FP2 processed:    0                                        ║
║   FP3 processed:    35                                       ║
╠══════════════════════════════════════════════════════════════╣
║                   APPLICATION BREAKDOWN                       ║
╠══════════════════════════════════════════════════════════════╣
║ Unknown               18  23.4% ####                         ║
║ Twitter/X             10  13.0% ##                           ║
║ DNS                    4   5.2% #                            ║
║ YouTube                3   3.9%                              ║
║ ...                                                          ║
╚══════════════════════════════════════════════════════════════╝
```

---

## 12. Extending the Project

- **QUIC / HTTP3 Expansion**: Parse full QUIC connection handshakes to extract SNIs from encrypted QUIC states.
- **Rules REST API**: Connect the `RuleManager` to a web framework (like FastAPI) to dynamically push and pull blocking rules.
