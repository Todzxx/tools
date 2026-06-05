# Network Inventory

A multi-engine network scanner and device inventory CLI that discovers and classifies devices on your local network. It uses ARP, ICMP, TCP sweeps, mDNS, SSDP, Nmap, DHCP lease scraping, SNMP, NetBIOS, and IPv6 Neighbor Discovery — no agents required.

[ID](README.id.md)

## Features

| Category | Feature |
|----------|---------|
| **Discovery** | ARP per-IP (256× parallel), ICMP ping, TCP sweep (16 ports), Nmap -sn -O, mDNS/Zeroconf (12+ service types), SSDP + UPnP descriptions, DHCP lease scraping (SNMP/HTTP/TP-Link/OpenWrt/Huawei/ZTE), IPv6 Neighbor Discovery, SNMP v2c probe, NetBIOS name queries |
| **Passive** | Wi-Fi scanning (pywifi), Bluetooth/BLE (bleak), ONVIF camera probing |
| **Fingerprinting** | Device type detection (40+ rules: port signatures + vendor patterns → Samsung, iPhone, Router, Printer, CCTV, etc.), OS detection (TTL + SSH/HTTP/FTP banners + keywords), MAC OUI vendor lookup, TLS certificate inspection, service version detection |
| **Output** | Rich console tables (`--pretty`), JSON, CSV, HTML dashboard (dark theme), Mermaid topology maps, SQLite history |
| **Monitoring** | Scan diff (new, removed, and changed devices between scans), live web dashboard |
| **CLI** | Live progress bar, client isolation diagnosis, configurable timeouts, concurrent 128-worker architecture |

## Installation

### Prerequisites
- Python ≥ 3.12
- Npcap (required for ARP via Scapy) — [npcap.com](https://npcap.com)
- Nmap (optional, for `--nmap`) — [nmap.org](https://nmap.org)

### Setup

```powershell
git clone <repo-url> network-inventory
cd network-inventory
pip install -e .
```

Or directly from a local folder:

```powershell
pip install -e D:\TUGAS\tools
```

## CLI Reference

```
network-inventory [OPTIONS] COMMAND [ARGS]...
```

### Commands

| Command | Description |
|---------|-------------|
| `scan` | Scan the network and discover all devices |
| `history` | View previous scan results from the database |
| `export` | Export all devices from the database to CSV or JSON |
| `map` | Generate a Mermaid topology map from the latest scan |
| `diff` | Compare two scans — shows new, removed, and changed devices |
| `serve` | Start a web dashboard to browse scan results |
| `init-config` | Generate a default `config.yaml` file |

### `scan` Options

| Flag | Default | Description |
|------|---------|-------------|
| `TARGET` | (required) | CIDR target, e.g. `192.168.1.0/24` |
| `--nmap` | `False` | Use Nmap -sn -O for host discovery |
| `--dhcp` | `False` | Scrape DHCP lease list from the router's web UI |
| `--snmp` | `False` | Probe devices via SNMP v2c |
| `--ipv6` | `False` | Enable IPv6 Neighbor Discovery |
| `--html / --no-html` | `True` | Generate an HTML report |
| `--pretty / --no-pretty` | `True` | Display Rich console tables |
| `--db / --no-db` | `True` | Save results to the SQLite database |
| `--timeout` | `2.0` | Port connection timeout in seconds |
| `--config` | `config.yaml` | Path to the YAML configuration file |

### Subcommand Details

#### `diff`
```powershell
network-inventory diff [SCAN_A] [SCAN_B] [--db-path PATH]
```
Compares two scans. If `SCAN_A` and `SCAN_B` are omitted, it compares the last two scans. Outputs new (green), removed (red), and changed (yellow) devices.

#### `serve`
```powershell
network-inventory serve [--host 127.0.0.1] [--port 8080] [--db-path PATH]
```
Starts a web dashboard in your browser. Tabs: Devices, Scan History, Diff, Topology.

#### `history`
```powershell
network-inventory history [--db-path PATH] [--limit 10]
```
Displays statistics and the device list from the SQLite database.

#### `export`
```powershell
network-inventory export [--format csv|json] [--output FILE] [--db-path PATH]
```
Exports all devices from the database to a CSV or JSON file.

#### `map`
```powershell
network-inventory map [--db-path PATH] [--output FILE.mmd]
```
Generates a Mermaid topology map file from the latest scan. Open it at [mermaid.live](https://mermaid.live) to visualize.

#### `init-config`
```powershell
network-inventory init-config
```
Creates a default `config.yaml` in the current directory.

## Usage Examples

```powershell
# Basic scan
network-inventory scan 192.168.1.0/24

# Full scan with all engines enabled
network-inventory scan 192.168.1.0/24 --nmap --dhcp --snmp --ipv6

# Quick scan (ARP + ICMP + TCP only)
network-inventory scan 192.168.1.0/24 --timeout 1.0

# Scan with history and HTML report
network-inventory scan 192.168.1.0/24 --html

# View differences between the last two scans
network-inventory diff

# Start the web dashboard
network-inventory serve

# Generate a topology map
network-inventory map

# Export the database
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
         │ ICMP ping│ │TCP sweep │ │ DHCP     │
         │ (system) │ │(16 ports)│ │ scrape   │
         └──────────┘ └──────────┘ └──────────┘
               │            │            │
               └────────────┼────────────┘
                            ▼
                     ┌──────────────┐
                     │  IPv6 ND     │ ← if --ipv6 is set
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
├── __init__.py           # Package exports (models, main entry)
├── __main__.py           # Enables `python -m network_inventory`
├── main.py               # CLI (Typer), 7 commands
├── models.py             # Pydantic models (DeviceRecord, ScanResult, etc.)
│
├── scanner/              # Discovery engines
│   ├── engine.py         # Orchestrator — runs 10 sequential stages
│   ├── arp_scanner.py    # ARP via Scapy + system arp -a fallback
│   ├── ipv6_scanner.py   # IPv6 neighbor discovery cache reader
│   ├── nmap_scanner.py   # Nmap -sn -O wrapper
│   ├── port_scanner.py   # Port scanner (50 common ports)
│   ├── router_scanner.py # DHCP lease scraper (multi-vendor support)
│   ├── mdns_scanner.py   # Zeroconf/mDNS (12+ service types)
│   ├── ssdp_scanner.py   # SSDP/UPnP discovery
│   ├── onvif_scanner.py  # ONVIF camera probe
│   ├── bluetooth_scanner.py  # BLE scanning via bleak
│   ├── wifi_scanner.py   # Wi-Fi scanning via pywifi
│   ├── snmp_scanner.py   # SNMP v2c probing
│   ├── netbios_scanner.py    # NetBIOS name queries
│   └── service_detector.py   # Service version detection
│
├── detectors/            # Classification and fingerprinting
│   ├── device_classifier.py  # 40+ rules: port + vendor patterns → device type
│   ├── os_detector.py        # TTL + banner + keyword OS detection
│   └── vendor_detector.py    # MAC OUI lookup
│
├── exporters/            # Output formatters
│   ├── json_exporter.py
│   ├── csv_exporter.py
│   ├── html_exporter.py      # Dark-themed HTML dashboard
│   ├── topology_exporter.py  # Mermaid topology diagrams
│   └── web_server.py         # Built-in web UI (serve command)
│
├── storage/
│   └── database.py           # SQLite database (scans, devices, device_history)
│
└── utils/
    ├── config.py         # Pydantic configuration (YAML load/save)
    ├── logger.py         # File and console logger
    ├── progress.py       # Rich live progress bar manager
    ├── dependencies.py   # Nmap and Npcap availability checker
    ├── permissions.py    # Administrative privileges checker
    ├── dns_utils.py      # Reverse DNS lookup
    └── tls_utils.py      # TLS certificate retrieval
```

## SQLite Database

The database stores device history across scans in `scan_history.db`:

| Table | Contents |
|-------|----------|
| `scans` | Each scan session (UUID id, target, timestamp, device_count) |
| `devices` | Unique device per MAC address (first_seen, last_seen, seen_count, last IP, type, OS, vendor) |
| `device_history` | Per-scan change log (IP, hostname, device_type, open_ports) |

The diff feature compares `device_history` entries between two scan IDs to determine which devices are new, removed, or changed.

## Web Dashboard

Start a web UI to browse scan results in your browser:

```powershell
network-inventory serve
# → http://127.0.0.1:8080
```

Tabs:
- **Devices** — All devices ever detected
- **Scan History** — All past scan sessions
- **Diff** — Device changes between the last two scans
- **Topology** — Network topology visualized as a hub-and-spoke graph

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

Generate the default configuration:

```powershell
network-inventory init-config
```

## Platform Notes

### Windows
- **Npcap is required** for ARP via Scapy. Download it from [npcap.com](https://npcap.com) and enable "Install in WinPcap API‑compatible Mode" during installation.
- **ICMP** uses `ping -n 1` (system fallback, no administrator privileges required).
- **Nmap** (optional) must be installed and available on your PATH.
- For the best progress bar experience, use **Windows Terminal** rather than the legacy cmd.exe.
- If the `network-inventory` command is not recognized, run it using the full path:
  ```powershell
  & "C:\Users\<user>\AppData\Local\Programs\Python\Python313\Scripts\network-inventory.exe"
  ```

### Linux / macOS
```bash
# ARP via Scapy requires elevated privileges
sudo network-inventory scan 192.168.1.0/24
```

### Client Isolation
If fewer than 3 devices are discovered (only the router and your own machine), AP/client isolation is likely enabled. Try the following:
1. Connect via an Ethernet cable
2. Run the scan from the router itself (SSH in and execute `arp -a`)
3. Disable AP isolation in your router's web interface

## Dependencies

| Package | Purpose |
|---------|---------|
| `scapy` | ARP packet injection |
| `rich` | Console tables and progress bars |
| `mac-vendor-lookup` | MAC OUI to vendor name resolution |
| `zeroconf` | mDNS service discovery |
| `dnspython` | DNS resolution |
| `requests` | HTTP requests for DHCP scraping, UPnP, and TLS |
| `python-nmap` | Nmap integration |
| `bleak` | Bluetooth/BLE discovery |
| `onvif-zeep` | ONVIF camera probing |
| `pywifi` | Wi-Fi scanning |
| `pysnmp` | SNMP v2c probing |
| `pydantic` | Data modeling and configuration |
| `typer` | CLI framework |
| `pyyaml` | YAML configuration file parsing |

## Development

```powershell
# Install development dependencies
pip install -e ".[dev]"

# Lint the codebase
ruff check network_inventory/

# Run the test suite (65 tests)
python -m pytest tests/ -q

# Run type checks
mypy network_inventory/

# Verify the CLI
network-inventory --help
```

## License

MIT
