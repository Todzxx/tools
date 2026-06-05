# Network Inventory

Multi-engine network scanner and device inventory CLI. Discovers and classifies devices on your local network using ARP, ICMP, TCP sweep, mDNS, SSDP, Nmap, DHCP lease scraping, SNMP, NetBIOS, and IPv6 Neighbor Discovery — agentless.

**Language:** EN · [ID](README.md)

## Features

| Category | Feature |
|----------|---------|
| **Discovery** | ARP per-IP (256× parallel), ICMP ping, TCP sweep (16 ports), Nmap -sn -O, mDNS/Zeroconf (12+ service types), SSDP + UPnP description, DHCP lease scraping (SNMP/HTTP/TP-Link/OpenWrt/Huawei/ZTE), IPv6 Neighbor Discovery, SNMP v2c probe, NetBIOS name query |
| **Passive** | Wi-Fi scan (pywifi), Bluetooth/BLE (bleak), ONVIF camera probe |
| **Fingerprinting** | Device type (40+ rules: port + vendor → Samsung, iPhone, Router, Printer, CCTV, etc.), OS detection (TTL + SSH/HTTP/FTP banner + keyword), MAC OUI vendor lookup, TLS certificate inspection, service version detection |
| **Output** | Rich console table (`--pretty`), JSON, CSV, HTML dashboard (dark theme), Mermaid topology map, SQLite history |
| **Monitoring** | Scan diff (new/removed/changed devices between scans), web dashboard real-time |
| **CLI** | Live progress bar, client isolation diagnosis, adjustable timeouts, concurrent 128-worker |

## Installation

### Requirements
- Python ≥ 3.12
- Npcap (for ARP via Scapy) — [npcap.com](https://npcap.com)
- Nmap (optional, for `--nmap`) — [nmap.org](https://nmap.org)

### Setup

```powershell
git clone <repo-url> network-inventory
cd network-inventory
pip install -e .
```

## CLI Reference

```
network-inventory [OPTIONS] COMMAND [ARGS]...
```

### Commands

| Command | Description |
|---------|-------------|
| `scan` | Scan network and discover all devices |
| `history` | View scan history from SQLite database |
| `export` | Export all devices from database to CSV/JSON |
| `map` | Generate Mermaid topology map from latest scan |
| `diff` | Compare two scans — show new/removed/changed devices |
| `serve` | Start web dashboard to browse scan results |
| `init-config` | Generate default config.yaml |

### `scan` Options

| Flag | Default | Description |
|------|---------|-------------|
| `TARGET` | (required) | CIDR target, e.g. `192.168.1.0/24` |
| `--nmap` | `False` | Use Nmap -sn -O for host discovery |
| `--dhcp` | `False` | Scrape DHCP lease list from router web UI |
| `--snmp` | `False` | Probe devices via SNMP v2c |
| `--ipv6` | `False` | IPv6 Neighbor Discovery |
| `--html / --no-html` | `True` | Generate HTML report |
| `--pretty / --no-pretty` | `True` | Show Rich tables |
| `--db / --no-db` | `True` | Save history to SQLite |
| `--timeout` | `2.0` | Port connection timeout (seconds) |
| `--config` | `config.yaml` | Path to YAML config file |

### Subcommands Detail

#### `diff`
```powershell
network-inventory diff [SCAN_A] [SCAN_B] [--db-path PATH]
```
Compare two scans. If SCAN_A and SCAN_B omitted, compares the last 2 scans. Output: new (green), removed (red), changed (yellow) devices.

#### `serve`
```powershell
network-inventory serve [--host 127.0.0.1] [--port 8080] [--db-path PATH]
```
Start web dashboard. Tabs: Devices, Scan History, Diff, Topology.

#### `history`
```powershell
network-inventory history [--db-path PATH] [--limit 10]
```
Show statistics and device list from SQLite database.

#### `export`
```powershell
network-inventory export [--format csv|json] [--output FILE] [--db-path PATH]
```
Export all devices from database to CSV or JSON file.

#### `map`
```powershell
network-inventory map [--db-path PATH] [--output FILE.mmd]
```
Generate Mermaid topology map file from latest scan. Open at [mermaid.live](https://mermaid.live) to visualize.

#### `init-config`
```powershell
network-inventory init-config
```
Create default `config.yaml` in current directory.

## Examples

```powershell
# Basic scan
network-inventory scan 192.168.1.0/24

# Full scan with all engines
network-inventory scan 192.168.1.0/24 --nmap --dhcp --snmp --ipv6

# Quick scan (ARP + ICMP + TCP only)
network-inventory scan 192.168.1.0/24 --timeout 1.0

# Scan + save to database + HTML report
network-inventory scan 192.168.1.0/24 --html

# View diff between last 2 scans
network-inventory diff

# Start web dashboard
network-inventory serve

# Generate topology map
network-inventory map

# Export database
network-inventory export --format json
```

## Discovery Pipeline

```
                     ┌──────────────┐
                     │   ARP per-IP  │ ← 256 parallel requests
                     └──────┬───────┘
                            │
               ┌────────────┼────────────┐
               ▼            ▼            ▼
         ┌──────────┐ ┌──────────┐ ┌──────────┐
         │ ICMP ping│ │TCP sweep │ │ Dhcp     │
         │ (system) │ │(16 ports)│ │ scrape   │
         └──────────┘ └──────────┘ └──────────┘
               │            │            │
               └────────────┼────────────┘
                            ▼
                     ┌──────────────┐
                     │  IPv6 ND     │ ← if --ipv6
                     └──────┬───────┘
                            ▼
               ┌──────────────────────┐
               │  Passive: mDNS ·     │
               │  SSDP · ONVIF · Wi-Fi│
               │  Bluetooth · NetBIOS │
               └──────────┬───────────┘
                          ▼
               ┌──────────────────────┐
               │  Enrichment: port    │
               │  scan · OS · vendor  │
               │  TLS · DNS · SNMP    │
               └──────────┬───────────┘
                          ▼
               ┌──────────────────────┐
               │  Export: JSON · CSV  │
               │  HTML · Mermaid · DB │
               └──────────────────────┘
```

## Architecture

```
network_inventory/
├── __init__.py           # Package exports (models, main)
├── __main__.py           # `python -m network_inventory` entry
├── main.py               # CLI (Typer), 7 commands
├── models.py             # Pydantic models (DeviceRecord, ScanResult, etc.)
│
├── scanner/              # Discovery engines
│   ├── engine.py         # Orchestrator — 10 sequential stages
│   ├── arp_scanner.py    # ARP via Scapy + system arp -a
│   ├── ipv6_scanner.py   # IPv6 ND cache reader
│   ├── nmap_scanner.py   # Nmap -sn -O wrapper
│   ├── port_scanner.py   # Port scanning (50 common ports)
│   ├── router_scanner.py # DHCP lease scraper (multi-vendor)
│   ├── mdns_scanner.py   # Zeroconf/mDNS (12+ service types)
│   ├── ssdp_scanner.py   # SSDP/UPnP discovery
│   ├── onvif_scanner.py  # ONVIF camera probe
│   ├── bluetooth_scanner.py  # BLE via bleak
│   ├── wifi_scanner.py   # Wi-Fi via pywifi
│   ├── snmp_scanner.py   # SNMP v2c probe
│   ├── netbios_scanner.py    # NetBIOS name query
│   └── service_detector.py   # Service version grabber
│
├── detectors/            # Classification & fingerprinting
│   ├── device_classifier.py  # 40+ rules: port + vendor → device type
│   ├── os_detector.py        # TTL + banner + keyword OS
│   └── vendor_detector.py    # MAC OUI lookup
│
├── exporters/            # Output formatters
│   ├── json_exporter.py
│   ├── csv_exporter.py
│   ├── html_exporter.py      # Dark theme HTML dashboard
│   ├── topology_exporter.py  # Mermaid topology diagram
│   └── web_server.py         # Built-in web UI (serve)
│
├── storage/
│   └── database.py           # SQLite (scans, devices, device_history)
│
└── utils/
    ├── config.py         # Pydantic config (YAML load/save)
    ├── logger.py         # File + console logger
    ├── progress.py       # Rich live progress bar manager
    ├── dependencies.py   # Nmap/Npcap checker
    ├── permissions.py    # Admin check
    ├── dns_utils.py      # Reverse DNS lookup
    └── tls_utils.py      # TLS certificate fetch
```

## SQLite Database

Database tracks device state across scans in `scan_history.db`:

| Table | Content |
|-------|---------|
| `scans` | Each scan session (UUID id, target, timestamp, device_count) |
| `devices` | Unique device per MAC (first_seen, last_seen, seen_count, last IP, type, OS, vendor) |
| `device_history` | Change log per scan (IP, hostname, device_type, open_ports) |

The diff feature compares `device_history` between two scan IDs to determine new, removed, or changed devices.

## Web Dashboard

Start a web UI to browse scan results in your browser:

```powershell
network-inventory serve
# → http://127.0.0.1:8080
```

Tabs:
- **Devices** — All devices ever detected
- **Scan History** — All scan sessions
- **Diff** — Device changes between last 2 scans
- **Topology** — Network topology (hub-and-spoke)

## YAML Configuration

Persistent configuration via `config.yaml`:

```yaml
scanner:
  allow_public: false
  max_hosts: 1024
  timeout: 2.0
  use_nmap: false
  use_dhcp: false
  use_snmp: false
  snmp_communities:
    - public
    - private
  db_path: scan_history.db

router:
  ip: 192.168.1.1
  username: admin
  password: admin

output_dir: results
```

Generate default: `network-inventory init-config`

## Platform Notes

### Windows
- **Npcap required** for ARP via Scapy. Install from [npcap.com](https://npcap.com) with "Install in WinPcap API‑compatible Mode" enabled.
- **ICMP** uses `ping -n 1` (system fallback, no admin required).
- **Nmap** (optional) must be installed and on PATH.
- Use **Windows Terminal** (not cmd.exe) for best progress bar display.
- If `network-inventory` command is not recognized, run via full path:
  ```powershell
  & "C:\Users\<user>\AppData\Local\Programs\Python\Python313\Scripts\network-inventory.exe"
  ```

### Linux / macOS
```bash
# Add sudo for ARP via Scapy
sudo network-inventory scan 192.168.1.0/24
```

### Client Isolation
If < 3 devices found (only router + your own machine), AP/client isolation is very likely active. Solutions:
1. Connect via Ethernet cable
2. Scan from the router (SSH in, run `arp -a`)
3. Disable AP isolation in router web UI

## Dependencies

| Package | Purpose |
|---------|---------|
| `scapy` | ARP packet injection |
| `rich` | Console table + progress bar |
| `mac-vendor-lookup` | MAC OUI → vendor name |
| `zeroconf` | mDNS service discovery |
| `dnspython` | DNS resolver |
| `requests` | HTTP for DHCP scraper, UPnP, TLS |
| `python-nmap` | Nmap wrapper |
| `bleak` | Bluetooth/BLE discovery |
| `onvif-zeep` | ONVIF camera probe |
| `pywifi` | Wi-Fi scan |
| `pysnmp` | SNMP v2c probe |
| `pydantic` | Data modeling & config |
| `typer` | CLI framework |
| `pyyaml` | Config file parser |

## Development

```powershell
# Setup dev dependencies
pip install -e ".[dev]"

# Lint
ruff check network_inventory/

# Test (65 tests)
python -m pytest tests/ -q

# Type check
mypy network_inventory/

# Verify CLI
network-inventory --help
```

## License

MIT
