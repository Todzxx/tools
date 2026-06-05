from __future__ import annotations

import json
import sqlite3
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Any


_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Network Inventory</title>
<style>
  :root {
    --bg: #0f172a; --surface: #1e293b; --border: #334155;
    --text: #e2e8f0; --muted: #94a3b8; --accent: #38bdf8;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: system-ui, sans-serif; padding: 1.5rem; }
  h1 { color: var(--accent); margin-bottom: 0.25rem; }
  .meta { color: var(--muted); font-size: 0.85rem; margin-bottom: 1.5rem; }
  .error { color: #ef4444; background: #1e293b; padding: 1rem; border-radius: 0.5rem; }
  .tabs { display: flex; gap: 0.5rem; margin-bottom: 1.5rem; flex-wrap: wrap; }
  .tab { background: var(--surface); border: 1px solid var(--border); padding: 0.5rem 1rem;
         border-radius: 0.4rem; cursor: pointer; color: var(--muted); font-size: 0.85rem; }
  .tab.active { background: var(--accent); color: #0f172a; font-weight: 600; border-color: var(--accent); }
  .tab:hover { border-color: var(--accent); }
  .panel { display: none; }
  .panel.active { display: block; }
  table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
  th { background: var(--surface); color: var(--muted); text-align: left;
       padding: 0.55rem 0.75rem; border-bottom: 1px solid var(--border); font-weight: 600; }
  td { padding: 0.5rem 0.75rem; border-bottom: 1px solid var(--border); vertical-align: top; }
  tr:hover td { background: #1e2d40; }
  .badge { display: inline-block; padding: 0.2rem 0.6rem; border-radius: 999px;
           font-size: 0.75rem; font-weight: 700; color: #0f172a; }
  .scan-card { background: var(--surface); border: 1px solid var(--border);
               border-radius: 0.5rem; padding: 1rem; margin-bottom: 0.75rem; }
  .scan-card .target { font-weight: 600; color: var(--accent); }
  .scan-card .info { color: var(--muted); font-size: 0.8rem; margin-top: 0.3rem; }
  .diff-new { border-left: 3px solid #22c55e; }
  .diff-removed { border-left: 3px solid #ef4444; opacity: 0.6; }
  .diff-changed { border-left: 3px solid #eab308; }
  footer { margin-top: 2rem; color: var(--muted); font-size: 0.8rem; text-align: center; }
</style>
</head>
<body>
  <h1>Network Inventory</h1>
  <p class="meta" id="subtitle">Loading...</p>

  <div class="tabs">
    <div class="tab active" onclick="switchTab('devices')">Devices</div>
    <div class="tab" onclick="switchTab('scans')">Scan History</div>
    <div class="tab" onclick="switchTab('diff')">Diff</div>
    <div class="tab" onclick="switchTab('topology')">Topology</div>
  </div>

  <div id="panel-devices" class="panel active"></div>
  <div id="panel-scans" class="panel"></div>
  <div id="panel-diff" class="panel"></div>
  <div id="panel-topology" class="panel"></div>

  <footer>network-inventory</footer>

<script>
let data = {};

function $(id) { return document.getElementById(id); }

async function load() {
  try {
    const resp = await fetch('/api/all');
    if (!resp.ok) throw new Error(`HTTP ${resp.status}: ${resp.statusText}`);
    data = await resp.json();
    const devs = data.devices || [];
    const scans = data.scans || [];
    $('subtitle').textContent = devs.length
      ? `${devs.length} devices tracked across ${scans.length} scans`
      : 'No data yet. Run a scan first: network-inventory scan 192.168.1.0/24';
    renderDevices();
    renderScans();
    renderDiff();
    renderTopology();
  } catch (e) {
    $('subtitle').innerHTML = `<span class="error">Failed to load data: ${e.message}</span>`;
  }
}

function switchTab(name) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  document.querySelector(`.tab[onclick*="'${name}'"]`).classList.add('active');
  $(`panel-${name}`).classList.add('active');
}

const TYPE_COLORS = {
  Router:"#f59e0b","Access Point":"#f59e0b","Windows PC":"#3b82f6","Mac":"#6366f1",
  Laptop:"#3b82f6",Desktop:"#3b82f6",Smartphone:"#10b981",Android:"#22c55e",
  iPhone:"#6366f1",Printer:"#8b5cf6",CCTV:"#ef4444",NAS:"#0ea5e9",
  "Smart TV":"#ec4899","Plex Server":"#f97316",IoT:"#14b8a6",Unknown:"#6b7280"
};

function badge(type) {
  const c = TYPE_COLORS[type] || "#6b7280";
  return `<span class="badge" style="background:${c}">${type}</span>`;
}

function esc(s) {
  const d = document.createElement('div');
  d.textContent = s ?? '';
  return d.innerHTML;
}

function renderDevices() {
  const devs = data.devices || [];
  if (!devs.length) { $('panel-devices').innerHTML = '<p class="meta">No devices.</p>'; return; }
  let html = '<table><thead><tr><th>IP</th><th>MAC</th><th>Vendor</th><th>Hostname</th><th>Type</th><th>OS</th><th>Last Seen</th></tr></thead><tbody>';
  for (const d of devs) {
    html += `<tr><td><strong>${esc(d.last_ip||'-')}</strong></td>
      <td><code>${esc(d.mac)}</code></td>
      <td>${esc(d.last_vendor||'-')}</td>
      <td>${esc(d.last_hostname||'-')}</td>
      <td>${badge(d.last_device_type)}</td>
      <td>${esc(d.last_os_family||'-')}</td>
      <td>${esc(d.last_seen||'-')}</td></tr>`;
  }
  html += '</tbody></table>';
  $('panel-devices').innerHTML = html;
}

function renderScans() {
  const scans = data.scans || [];
  if (!scans.length) { $('panel-scans').innerHTML = '<p class="meta">No scans yet.</p>'; return; }
  let html = '';
  for (const s of scans) {
    const dur = s.finished_at ? `${((new Date(s.finished_at)-new Date(s.started_at))/1000).toFixed(0)}s` : '-';
    html += `<div class="scan-card"><div class="target">${esc(s.target)}</div>
      <div class="info">${esc(s.started_at)} &middot; ${s.device_count} devices &middot; ${dur}</div></div>`;
  }
  $('panel-scans').innerHTML = html;
}

function renderDiff() {
  const d = data.diff || {};
  const total = (d.new?.length||0)+(d.removed?.length||0)+(d.changed?.length||0);
  if (!total) { $('panel-diff').innerHTML = '<p class="meta">No changes between last two scans.</p>'; return; }
  let html = '';
  if (d.new?.length) {
    html += `<h3 style="color:#22c55e">+ New (${d.new.length})</h3><table><tbody>`;
    for (const dev of d.new) html += `<tr class="diff-new"><td><code>${esc(dev.mac||dev.ip_address)}</code></td><td>${esc(dev.ip_address)}</td><td>${badge(dev.device_type)}</td></tr>`;
    html += '</tbody></table>';
  }
  if (d.removed?.length) {
    html += `<h3 style="color:#ef4444;margin-top:1rem">- Removed (${d.removed.length})</h3><table><tbody>`;
    for (const dev of d.removed) html += `<tr class="diff-removed"><td><code>${esc(dev.mac||dev.ip_address)}</code></td><td>${esc(dev.ip_address)}</td><td>${badge(dev.device_type)}</td></tr>`;
    html += '</tbody></table>';
  }
  if (d.changed?.length) {
    html += `<h3 style="color:#eab308;margin-top:1rem">~ Changed (${d.changed.length})</h3><table><tbody>`;
    for (const c of d.changed) {
      const a=c.before, b=c.after;
      html += `<tr class="diff-changed"><td><code>${esc(a.mac||a.ip_address)}</code></td><td>${esc(a.ip_address)} → ${esc(b.ip_address)}</td><td>${badge(a.device_type)} → ${badge(b.device_type)}</td></tr>`;
    }
    html += '</tbody></table>';
  }
  $('panel-diff').innerHTML = html;
}

function renderTopology() {
  const devs = data.devices || [];
  if (!devs.length) { $('panel-topology').innerHTML = '<p class="meta">No devices to draw.</p>'; return; }
  const gw = devs.find(d=>d.last_device_type==='Router')||devs[0];
  let mmd = 'graph TD\\n';
  for (const d of devs) {
    const nid = (d.last_ip||d.mac).replace(/\\./g,'_');
    mmd += `    ${nid}["${d.last_hostname||d.last_ip}<br/>${d.last_ip}"]\\n`;
  }
  for (const d of devs) {
    const nid = (d.last_ip||d.mac).replace(/\\./g,'_');
    const gid = (gw.last_ip||'gw').replace(/\\./g,'_');
    if (nid!==gid) mmd += `    ${gid} --- ${nid}\\n`;
  }
  const url = `https://mermaid.ink/img/${btoa(mmd)}`;
  $('panel-topology').innerHTML = `<p class="meta">Network topology</p><img src="${url}" style="max-width:100%;background:white;border-radius:0.5rem;padding:1rem;" onerror="this.outerHTML='<p class=meta>Could not render topology.</p>'">`;
}

load();
</script>
</body>
</html>
"""


class _Handler(BaseHTTPRequestHandler):
    db_path: str = ""

    def _send_json(self, data: Any, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data, default=str).encode())

    def _send_error(self, msg: str, status: int = 500) -> None:
        self._send_json({"error": msg}, status)

    def _get_db(self) -> sqlite3.Connection | None:
        if not self.db_path or not Path(self.db_path).exists():
            return None
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            return conn
        except Exception:
            return None

    def _query(self, sql: str, params: tuple = ()) -> list[dict[str, Any]]:
        conn = self._get_db()
        if not conn:
            return []
        try:
            rows = conn.execute(sql, params).fetchall()
            return [dict(r) for r in rows]
        except Exception:
            return []
        finally:
            conn.close()

    def _diff(self) -> dict[str, Any]:
        conn = self._get_db()
        if not conn:
            return {"new": [], "removed": [], "changed": []}
        try:
            scans = conn.execute(
                "SELECT id FROM scans ORDER BY started_at DESC LIMIT 2"
            ).fetchall()
            if len(scans) < 2:
                return {"new": [], "removed": [], "changed": []}

            scan_a, scan_b = scans[1]["id"], scans[0]["id"]

            def get_scan(scan_id: str) -> dict[str, dict[str, Any]]:
                rows = conn.execute(
                    "SELECT * FROM device_history WHERE scan_id = ?", (scan_id,)
                ).fetchall()
                return {(r["mac"] or r["ip_address"]).upper(): dict(r) for r in rows}

            a_map = get_scan(scan_a)
            b_map = get_scan(scan_b)
            a_keys, b_keys = set(a_map), set(b_map)

            new_devs = [b_map[k] for k in b_keys - a_keys]
            removed_devs = [a_map[k] for k in a_keys - b_keys]

            changed = []
            for k in a_keys & b_keys:
                a, b = a_map[k], b_map[k]
                if any(
                    a.get(f) != b.get(f)
                    for f in ("ip_address", "hostname", "device_type", "vendor")
                ):
                    changed.append({"before": a, "after": b})

            return {"new": new_devs, "removed": removed_devs, "changed": changed}
        finally:
            conn.close()

    def do_GET(self) -> None:
        try:
            if self.path in ("/", "/index.html"):
                return self._send_html()
            if self.path == "/api/all":
                return self._send_json(
                    {
                        "devices": self._query(
                            "SELECT * FROM devices ORDER BY last_seen DESC"
                        ),
                        "scans": self._query(
                            "SELECT * FROM scans ORDER BY started_at DESC LIMIT 20"
                        ),
                        "diff": self._diff(),
                    }
                )
            self._send_error("Not found", 404)
        except Exception as e:
            self._send_error(str(e))

    def _send_html(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(_HTML.encode("utf-8"))

    def log_message(self, format: str, *args: Any) -> None:
        pass


def serve(db_path: str, host: str = "127.0.0.1", port: int = 8080) -> None:
    _Handler.db_path = db_path
    server = HTTPServer((host, port), _Handler)
    print(f"  Web UI: http://{host}:{port}")
    print(f"  Database: {Path(db_path).resolve()}")
    print("  Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()
