from __future__ import annotations

import html
from collections import Counter
from datetime import datetime
from pathlib import Path

from network_inventory.models import ScanResult


# ── Device-type colour map ─────────────────────────────────────────────────────
DEVICE_COLOR: dict[str, str] = {
    "Router": "#f59e0b",
    "Access Point": "#f59e0b",
    "Windows PC": "#3b82f6",
    "Mac": "#6366f1",
    "Laptop": "#3b82f6",
    "Desktop": "#3b82f6",
    "Smartphone": "#10b981",
    "Android": "#22c55e",
    "iPhone": "#6366f1",
    "Printer": "#8b5cf6",
    "CCTV": "#ef4444",
    "NAS": "#0ea5e9",
    "Smart TV": "#ec4899",
    "Plex Server": "#f97316",
    "IoT": "#14b8a6",
    "Unknown": "#6b7280",
}

_STYLE = """
<style>
  :root {
    --bg: #0f172a; --surface: #1e293b; --border: #334155;
    --text: #e2e8f0; --muted: #94a3b8; --accent: #38bdf8;
    --font: 'Inter', system-ui, sans-serif;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: var(--font); padding: 2rem; }
  h1 { font-size: 1.6rem; margin-bottom: 0.25rem; color: var(--accent); }
  .meta { color: var(--muted); font-size: .85rem; margin-bottom: 2rem; }
  section { margin-bottom: 2.5rem; }
  h2 { font-size: 1.1rem; color: var(--accent); border-bottom: 1px solid var(--border);
       padding-bottom: .4rem; margin-bottom: 1rem; }
  table { width: 100%; border-collapse: collapse; font-size: .85rem; }
  th { background: var(--surface); color: var(--muted); text-align: left;
       padding: .55rem .75rem; border-bottom: 1px solid var(--border); font-weight: 600; }
  td { padding: .5rem .75rem; border-bottom: 1px solid var(--border); vertical-align: top; }
  tr:hover td { background: #1e2d40; }
  .badge { display: inline-block; padding: .2rem .6rem; border-radius: 999px;
           font-size: .75rem; font-weight: 700; color: #0f172a; }
  .ports { display: flex; flex-wrap: wrap; gap: .25rem; }
  .port-chip { background: #1e293b; border: 1px solid var(--border);
               border-radius: .3rem; padding: .1rem .4rem; font-size: .75rem; }
  .notes { color: var(--muted); font-size:.8rem; }
  .wifi-badge { background: #1e293b; border: 1px solid var(--border);
                border-radius: .25rem; padding: .15rem .5rem;
                font-size:.75rem; display:inline-block; }
  .enc-wpa3  { color:#22c55e; } .enc-wpa2 { color:#3b82f6; }
  .enc-wpa   { color:#f59e0b; } .enc-open { color:#ef4444; }
  footer { margin-top: 3rem; color: var(--muted); font-size: .8rem; text-align: center; }
</style>
"""


def _badge(device_type: str) -> str:
    color = DEVICE_COLOR.get(device_type, "#6b7280")
    label = html.escape(device_type)
    return f'<span class="badge" style="background:{color}">{label}</span>'


def _enc_class(enc: str) -> str:
    enc_upper = enc.upper()
    if "WPA3" in enc_upper:
        return "enc-wpa3"
    if "WPA2" in enc_upper:
        return "enc-wpa2"
    if "WPA" in enc_upper:
        return "enc-wpa"
    return "enc-open"


def export_html(result: ScanResult, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    scan_time = result.started_at
    duration = ""
    if result.finished_at:
        try:
            t0 = datetime.fromisoformat(result.started_at)
            t1 = datetime.fromisoformat(result.finished_at)
            duration = f" — scan took {int((t1 - t0).total_seconds())}s"
        except Exception:
            pass

    rows: list[str] = []
    for dev in result.devices:
        ports_html = "".join(
            f'<span class="port-chip">{p.port}/{html.escape(p.service)}'
            + (f" <em>{html.escape(p.version)}</em>" if p.version else "")
            + "</span>"
            for p in dev.open_ports
        )
        ports_cell = f'<div class="ports">{ports_html}</div>' if ports_html else "-"

        tls_cell = "-"
        if dev.tls:
            cn = html.escape(dev.tls.common_name or "-")
            issuer = html.escape(dev.tls.issuer or "-")
            status = "⚠ expired" if dev.tls.expired else "✓ valid"
            tls_cell = f"<small>{cn}<br><span style='color:var(--muted)'>{issuer}</span><br>{status}</small>"

        notes_html = "<br>".join(html.escape(n) for n in dev.notes)
        notes_cell = f'<div class="notes">{notes_html}</div>' if notes_html else "-"

        os_label = html.escape(dev.os_family or "-")
        ttl_label = f" (TTL:{dev.ttl})" if dev.ttl is not None else ""
        os_cell = f"{os_label}<span style='color:var(--muted);font-size:.7rem'>{html.escape(ttl_label)}</span>"

        ipv6_cell = html.escape(dev.ipv6_address or "-")
        if dev.ipv6_address:
            ipv6_cell = f"<code style='font-size:.75rem'>{ipv6_cell}</code>"

        rows.append(
            f"<tr>"
            f"<td><strong>{html.escape(dev.ip_address)}</strong></td>"
            f"<td>{ipv6_cell}</td>"
            f"<td><code>{html.escape(dev.mac_address or '-')}</code></td>"
            f"<td>{html.escape(dev.vendor or '-')}</td>"
            f"<td>{html.escape(dev.hostname or '-')}</td>"
            f"<td>{_badge(dev.device_type)}</td>"
            f"<td>{os_cell}</td>"
            f"<td>{ports_cell}</td>"
            f"<td>{tls_cell}</td>"
            f"<td>{notes_cell}</td>"
            f"</tr>"
        )

    devices_table = (
        "<table><thead><tr>"
        "<th>IP</th><th>IPv6</th><th>MAC</th><th>Vendor</th><th>Hostname</th>"
        "<th>Type</th><th>OS</th><th>Open Ports</th><th>TLS</th><th>Notes</th>"
        "</tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
    )

    wifi_rows: list[str] = []
    for net in result.wifi_networks:
        enc_cls = _enc_class(net.encryption)
        freq_label = f"{net.frequency} MHz" if net.frequency else "-"
        signal_label = f"{net.signal} dBm" if net.signal is not None else "-"
        wifi_rows.append(
            f"<tr>"
            f"<td><strong>{html.escape(net.ssid or '-')}</strong></td>"
            f"<td><code>{html.escape(net.bssid or '-')}</code></td>"
            f"<td>{html.escape(str(net.channel) if net.channel is not None else '-')}</td>"
            f"<td>{html.escape(freq_label)}</td>"
            f"<td>{html.escape(signal_label)}</td>"
            f"<td><span class='{enc_cls}'>{html.escape(net.encryption)}</span></td>"
            f"</tr>"
        )
    wifi_section = ""
    if wifi_rows:
        wifi_section = (
            "<section><h2>📶 Wi-Fi Networks</h2>"
            "<table><thead><tr>"
            "<th>SSID</th><th>BSSID</th><th>Channel</th>"
            "<th>Frequency</th><th>Signal</th><th>Encryption</th>"
            "</tr></thead><tbody>" + "".join(wifi_rows) + "</tbody></table></section>"
        )

    bt_rows: list[str] = []
    for bt in result.bluetooth_devices:
        bt_rows.append(
            f"<tr>"
            f"<td>{html.escape(bt.name or '-')}</td>"
            f"<td><code>{html.escape(bt.address)}</code></td>"
            f"<td>{html.escape(str(bt.rssi) if bt.rssi is not None else '-')} dBm</td>"
            f"</tr>"
        )
    bt_section = ""
    if bt_rows:
        bt_section = (
            "<section><h2>🔵 Bluetooth / BLE Devices</h2>"
            "<table><thead><tr><th>Name</th><th>Address</th><th>RSSI</th></tr></thead>"
            "<tbody>" + "".join(bt_rows) + "</tbody></table></section>"
        )

    type_counts = Counter(dev.device_type for dev in result.devices)
    stat_chips = " ".join(
        f'<span class="wifi-badge">{_badge(t)} &times;{c}</span>'
        for t, c in sorted(type_counts.items())
    )

    body = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Network Inventory — {html.escape(result.target)}</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
  {_STYLE}
</head>
<body>
  <h1>🌐 Network Inventory</h1>
  <p class="meta">Target: <strong>{html.escape(result.target)}</strong> &nbsp;|&nbsp;
     Scanned: {html.escape(scan_time)}{html.escape(duration)} &nbsp;|&nbsp;
     Devices found: <strong>{len(result.devices)}</strong></p>
  <p style="margin-bottom:1.5rem">{stat_chips}</p>

  <section>
    <h2>🖥 Devices</h2>
    {devices_table}
  </section>

  {wifi_section}
  {bt_section}

  <footer>Generated by network-inventory &nbsp;·&nbsp; {html.escape(scan_time)}</footer>
</body>
</html>
"""
    output_path.write_text(body, encoding="utf-8")
