# Network Inventory

Multi-engine network scanner dan device inventory CLI. Menemukan dan mengklasifikasikan perangkat di jaringan lokal menggunakan ARP, ICMP, TCP sweep, mDNS, SSDP, Nmap, DHCP lease scraping, SNMP, NetBIOS, dan IPv6 Neighbor Discovery — tanpa agen.

**Bahasa:** ID · [EN](README.en.md)

## Fitur

| Kategori | Fitur |
|----------|-------|
| **Discovery** | ARP per-IP (256× paralel), ICMP ping, TCP sweep (16 port), Nmap -sn -O, mDNS/Zeroconf (12+ service types), SSDP + UPnP description, DHCP lease scraping (SNMP/HTTP/TP-Link/OpenWrt/Huawei/ZTE), IPv6 Neighbor Discovery, SNMP v2c probe, NetBIOS name query |
| **Passive** | Wi-Fi scan (pywifi), Bluetooth/BLE (bleak), ONVIF camera probe |
| **Fingerprinting** | Device type (40+ rule: port + vendor → Samsung, iPhone, Router, Printer, CCTV, dll), OS detection (TTL + banner SSH/HTTP/FTP + keyword), MAC OUI vendor lookup, TLS certificate inspection, service version detection |
| **Output** | Rich console table (`--pretty`), JSON, CSV, HTML dashboard (dark theme), Mermaid topology map, SQLite history |
| **Monitoring** | Scan diff (device baru/hilang/berubah antar scan), web dashboard real-time |
| **CLI** | Progress bar live, client isolation diagnosis, timeout control, concurrent 128-worker |

## Instalasi

### Persyaratan
- Python ≥ 3.12
- Npcap (untuk ARP via Scapy) — [npcap.com](https://npcap.com)
- Nmap (opsional, untuk `--nmap`) — [nmap.org](https://nmap.org)

### Setup

```powershell
git clone <repo-url> network-inventory
cd network-inventory
pip install -e .
```

Atau tanpa clone:
```powershell
pip install -e D:\TUGAS\tools
```

## CLI Reference

```
network-inventory [OPTIONS] COMMAND [ARGS]...
```

### Commands

| Command | Deskripsi |
|---------|-----------|
| `scan` | Scan jaringan dan temukan semua perangkat |
| `history` | Lihat riwayat scan sebelumnya dari database |
| `export` | Export semua device dari database ke CSV/JSON |
| `map` | Generate topology map (Mermaid) dari scan terakhir |
| `diff` | Bandingkan dua scan — tunjukkan device baru/hilang/berubah |
| `serve` | Jalankan web dashboard untuk browse hasil scan |
| `init-config` | Generate file config.yaml default |

### `scan` Options

| Flag | Default | Deskripsi |
|------|---------|-----------|
| `TARGET` | (required) | CIDR target, contoh: `192.168.1.0/24` |
| `--nmap` | `False` | Gunakan Nmap -sn -O untuk host discovery |
| `--dhcp` | `False` | Scrape daftar DHCP dari web UI router |
| `--snmp` | `False` | Probe device via SNMP v2c |
| `--ipv6` | `False` | IPv6 Neighbor Discovery |
| `--html / --no-html` | `True` | Generate HTML report |
| `--pretty / --no-pretty` | `True` | Tampilkan tabel Rich |
| `--db / --no-db` | `True` | Simpan history ke SQLite |
| `--timeout` | `2.0` | Timeout koneksi port (detik) |
| `--config` | `config.yaml` | Path ke file konfigurasi YAML |

### Subcommands Detail

#### `diff`
```powershell
network-inventory diff [SCAN_A] [SCAN_B] [--db-path PATH]
```
Bandingkan dua scan. Jika SCAN_A dan SCAN_B tidak diberikan, membandingkan 2 scan terakhir. Output: device baru (hijau), hilang (merah), berubah (kuning).

#### `serve`
```powershell
network-inventory serve [--host 127.0.0.1] [--port 8080] [--db-path PATH]
```
Jalankan web dashboard di browser. Tab: Devices, Scan History, Diff, Topology.

#### `history`
```powershell
network-inventory history [--db-path PATH] [--limit 10]
```
Tampilkan statistik dan daftar device dari database SQLite.

#### `export`
```powershell
network-inventory export [--format csv|json] [--output FILE] [--db-path PATH]
```
Export semua device dari database ke file CSV atau JSON.

#### `map`
```powershell
network-inventory map [--db-path PATH] [--output FILE.mmd]
```
Generate file Mermaid topology map dari scan terakhir. Buka di [mermaid.live](https://mermaid.live) untuk visualisasi.

#### `init-config`
```powershell
network-inventory init-config
```
Buat file `config.yaml` default di direktori saat ini.

## Contoh Penggunaan

```powershell
# Scan dasar
network-inventory scan 192.168.1.0/24

# Scan lengkap dengan semua engine
network-inventory scan 192.168.1.0/24 --nmap --dhcp --snmp --ipv6

# Quick scan (hanya ARP + ICMP + TCP)
network-inventory scan 192.168.1.0/24 --timeout 1.0

# Scan + simpan history + HTML report
network-inventory scan 192.168.1.0/24 --html

# Lihat perbedaan antara 2 scan terakhir
network-inventory diff

# Buka web dashboard
network-inventory serve

# Generate topology map
network-inventory map

# Export database
network-inventory export --format json
```

## Pipeline Discovery

```
                     ┌──────────────┐
                     │   ARP per-IP  │ ← 256 request paralel
                     └──────┬───────┘
                            │
               ┌────────────┼────────────┐
               ▼            ▼            ▼
         ┌──────────┐ ┌──────────┐ ┌──────────┐
         │ ICMP ping│ │TCP sweep │ │ Dhcp     │
         │ (system) │ │(16 port) │ │ scrape   │
         └──────────┘ └──────────┘ └──────────┘
               │            │            │
               └────────────┼────────────┘
                            ▼
                     ┌──────────────┐
                     │  IPv6 ND     │ ← jika --ipv6
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

## Arsitektur

```
network_inventory/
├── __init__.py           # Package exports (models, main)
├── __main__.py           # `python -m network_inventory` entry
├── main.py               # CLI (Typer), 7 commands
├── models.py             # Pydantic models (DeviceRecord, ScanResult, dll.)
│
├── scanner/              # Discovery engines
│   ├── engine.py         # Orchestrator — 10 stages berurutan
│   ├── arp_scanner.py    # ARP via Scapy + system arp -a
│   ├── ipv6_scanner.py   # IPv6 ND cache reader
│   ├── nmap_scanner.py   # Nmap -sn -O wrapper
│   ├── port_scanner.py   # Port scanning (50 port umum)
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
├── detectors/            # Klasifikasi & fingerprinting
│   ├── device_classifier.py  # 40+ rule: port + vendor → device type
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

Database menyimpan riwayat perangkat antar scan di `scan_history.db`:

| Tabel | Isi |
|-------|-----|
| `scans` | Setiap sesi scan (id UUID, target, timestamp, device_count) |
| `devices` | Data perangkat unik per MAC (first_seen, last_seen, seen_count, IP terakhir, type, OS, vendor) |
| `device_history` | Riwayat perubahan per scan (IP, hostname, device_type, open_ports) |

Fitur diff membandingkan `device_history` antar dua scan ID untuk menentukan device yang baru, hilang, atau berubah.

## Web Dashboard

Jalankan web UI untuk browse hasil scan di browser:

```powershell
network-inventory serve
# → http://127.0.0.1:8080
```

Tab:
- **Devices** — Semua device yang pernah terdeteksi
- **Scan History** — Riwayat semua scan
- **Diff** — Perubahan device antar 2 scan terakhir
- **Topology** — Topologi jaringan (hub-and-spoke)

## Konfigurasi YAML

File `config.yaml` memungkinkan konfigurasi persisten:

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
- **Npcap diperlukan** untuk ARP via Scapy. Install dari [npcap.com](https://npcap.com) dengan opsi "Install in WinPcap API‑compatible Mode".
- **ICMP** menggunakan `ping -n 1` (system fallback, tanpa perlu admin).
- **Nmap** (opsional) harus terinstall dan terdaftar di PATH.
- Gunakan **Windows Terminal** (bukan cmd.exe) untuk hasil progress bar terbaik.
- Jika `network-inventory` command tidak dikenali, jalankan via path lengkap:
  ```powershell
  & "C:\Users\<user>\AppData\Local\Programs\Python\Python313\Scripts\network-inventory.exe"
  ```

### Linux / macOS
```bash
# Tambahkan sudo untuk ARP via Scapy
sudo network-inventory scan 192.168.1.0/24
```

### Client Isolation
Jika hanya < 3 perangkat yang ditemukan (router + laptop sendiri), kemungkinan AP/client isolation aktif. Solusi:
1. Gunakan kabel LAN
2. Scan dari router (SSH ke router, jalankan `arp -a`)
3. Matikan AP isolation di web UI router

## Dependencies

| Package | Untuk |
|---------|-------|
| `scapy` | ARP packet injection |
| `rich` | Console table + progress bar |
| `mac-vendor-lookup` | MAC OUI → vendor name |
| `zeroconf` | mDNS service discovery |
| `dnspython` | DNS resolver |
| `requests` | HTTP untuk DHCP scraper, UPnP, TLS |
| `python-nmap` | Nmap wrapper |
| `bleak` | Bluetooth/BLE discovery |
| `onvif-zeep` | ONVIF camera probe |
| `pywifi` | Wi-Fi scan |
| `pysnmp` | SNMP v2c probe |
| `pydantic` | Data modeling & config |
| `typer` | CLI framework |
| `pyyaml` | Config file parser |

## Pengembangan

```powershell
# Setup dev dependencies
pip install -e ".[dev]"

# Lint
ruff check network_inventory/

# Test
python -m pytest tests/ -v

# Test (65 test)
python -m pytest tests/ -q

# Type check
mypy network_inventory/

# Verifikasi CLI
network-inventory --help
```

## Lisensi

MIT
