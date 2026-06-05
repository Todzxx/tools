from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich.live import Live

from network_inventory.models import ScanResult
from network_inventory.scanner.engine import ScannerEngine
from network_inventory.utils.logger import setup_logger
from network_inventory.utils.progress import ProgressManager
from network_inventory.utils.dependencies import DependencyChecker
from network_inventory.utils.permissions import PermissionChecker
from network_inventory.utils.config import ConfigManager, AppConfig
from network_inventory.exporters.csv_exporter import export_csv
from network_inventory.exporters.json_exporter import export_json
from network_inventory.exporters.html_exporter import export_html
from network_inventory.exporters.topology_exporter import TopologyExporter


app = typer.Typer(
    help="Professional Network Inventory & Mapping Tool",
    add_completion=True,
    rich_markup_mode="rich"
)

console = Console()

DEVICE_STYLE: dict[str, str] = {
    "Router":       "bold yellow",
    "Access Point": "yellow",
    "Windows PC":   "bold cyan",
    "Mac":          "bold magenta",
    "Laptop":       "cyan",
    "Desktop":      "cyan",
    "Smartphone":   "bold green",
    "Android":      "green",
    "iPhone":       "magenta",
    "Printer":      "purple",
    "CCTV":         "bold red",
    "NAS":          "bold blue",
    "Smart TV":     "bright_magenta",
    "Plex Server":  "bold orange3",
    "IoT":          "bold cyan",
    "Unknown":      "dim white",
}


def display_summary_table(result: ScanResult) -> None:
    table = Table(title=f"Scan Result: {result.target}", show_header=True, header_style="bold magenta")
    table.add_column("IP Address", style="cyan")
    table.add_column("MAC Address", style="green")
    table.add_column("Vendor", style="yellow")
    table.add_column("Hostname", style="blue")
    table.add_column("Type", style="bold")
    table.add_column("OS", style="magenta")

    for dev in sorted(result.devices, key=lambda x: x.ip_address):
        style = DEVICE_STYLE.get(dev.device_type, "white")
        table.add_row(
            dev.ip_address,
            dev.mac_address or "-",
            dev.vendor or "-",
            dev.hostname or "-",
            f"[{style}]{dev.device_type}[/{style}]",
            dev.os_family or "-",
        )
    console.print(table)


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target CIDR (e.g., 192.168.1.0/24)"),
    nmap: bool = typer.Option(False, "--nmap", help="Use Nmap for fingerprinting"),
    dhcp: bool = typer.Option(False, "--dhcp", help="Scrape DHCP leases from router"),
    snmp: bool = typer.Option(False, "--snmp", help="Probe devices via SNMP"),
    ipv6: bool = typer.Option(False, "--ipv6", help="Enable IPv6 discovery"),
    html: bool = typer.Option(True, "--html/--no-html", help="Generate HTML report"),
    pretty: bool = typer.Option(True, "--pretty/--no-pretty", help="Show rich table output"),
    save_db: bool = typer.Option(True, "--db/--no-db", help="Save results to history database"),
    timeout: float = typer.Option(2.0, help="Timeout for port scans"),
    config_file: Optional[Path] = typer.Option(None, "--config", help="Path to config.yaml"),
):
    """
    Perform a complete network scan and map all discovered devices.
    """
    logger = setup_logger()
    
    # Load Config
    cfg_manager = ConfigManager(config_file)
    cfg = cfg_manager.load()

    # Merge config with CLI flags
    options = cfg.scanner.model_dump()
    options.update({
        "use_nmap": nmap or options["use_nmap"],
        "use_dhcp": dhcp or options["use_dhcp"],
        "use_snmp": snmp or options["use_snmp"],
        "use_ipv6": ipv6 or options["use_ipv6"],
        "timeout": timeout,
        "router_ip": cfg.router.ip,
        "router_username": cfg.router.username,
        "router_password": cfg.router.password,
        "output_html": html,
    })

    # Dependency & Permission Checks
    missing = DependencyChecker.get_missing_dependencies()
    if options["use_nmap"] and "Nmap" in str(missing):
        console.print("[yellow]Warning: Nmap is not installed. Skipping Nmap scan.[/yellow]")
        options["use_nmap"] = False

    perm_warning = PermissionChecker.get_permission_warning()
    if perm_warning:
        console.print(f"[yellow]Warning: {perm_warning}[/yellow]")

    # Run Scan
    progress_manager = ProgressManager()
    engine = ScannerEngine(logger, progress_manager)

    async def _run():
        try:
            try:
                with Live(progress_manager.get_renderable(), refresh_per_second=4, transient=True) as live:
                    progress_manager._live = live
                    return await engine.run(target, options)
            except UnicodeEncodeError:
                # Fallback if terminal cannot render Unicode spinners
                with Live(progress_manager.get_renderable(), refresh_per_second=2, transient=True) as live:
                    progress_manager._live = live
                    return await engine.run(target, options)
        except ValueError as e:
            console.print(f"[red]Error: {e}[/red]")
            sys.exit(1)
        except Exception as e:
            logger.exception("Unexpected error")
            console.print(f"[bold red]Unexpected Error:[/bold red] {e}")
            sys.exit(1)

    result = asyncio.run(_run())

    # Post-process
    if pretty:
        if len(result.devices) <= 2:
            console.print(f"\n[yellow]Hint: Only {len(result.devices)} devices found. If you expect more (HP/Laptop), [/yellow]")
            console.print("[yellow]check if 'AP Isolation' or 'Guest Network' is active on your router.[/yellow]\n")
        if result.devices:
            display_summary_table(result)
        else:
            console.print("[yellow]No devices discovered.[/yellow]")
    else:
        console.print(f"[bold green]Scan Complete:[/bold green] Found {len(result.devices)} devices.")

    # Export
    output_dir = Path(cfg.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    json_path = output_dir / "scan_result.json"
    csv_path = output_dir / "scan_result.csv"
    
    export_json(result, json_path)
    export_csv(result, csv_path)
    console.print(f"Results exported to [cyan]{output_dir}[/cyan]")

    if options.get("output_html", True):
        html_path = output_dir / "scan_result.html"
        export_html(result, html_path)
        console.print(f"HTML report saved to [cyan]{html_path}[/cyan]")

    if save_db:
        from network_inventory.storage.database import ScanDatabase
        db = ScanDatabase(options["db_path"])
        db.save_scan(result)
        console.print(f"History saved to [cyan]{options['db_path']}[/cyan]")


@app.command()
def history(
    db_path: str = typer.Option("scan_history.db", help="Path to SQLite database"),
    limit: int = typer.Option(10, help="Number of recent scans to show"),
):
    """
    View summary of previous scan results from the database.
    """
    from network_inventory.storage.database import ScanDatabase
    db = ScanDatabase(db_path)
    db.open()
    
    stats = db.get_stats()
    if not stats or not stats.get("total_devices"):
        console.print("[yellow]No history found in database.[/yellow]")
        return

    console.print("[bold cyan]Scan History Statistics:[/bold cyan]")
    console.print(f"  Total devices seen: [green]{stats['total_devices']}[/green]")
    console.print(f"  Device types identified: [green]{stats['device_types']}[/green]")
    console.print(f"  Last scan date: [green]{stats['last_scan']}[/green]")
    
    table = Table(title="Known Devices (Most Recent)", show_header=True, header_style="bold magenta")
    table.add_column("Last IP", style="cyan")
    table.add_column("MAC Address", style="green")
    table.add_column("Vendor", style="yellow")
    table.add_column("Type", style="bold")
    table.add_column("First Seen", style="dim")
    table.add_column("Seen Count", style="blue")

    devices = db.get_all_devices()[:limit]
    for dev in devices:
        table.add_row(
            dev["last_ip"] or "-",
            dev["mac"],
            dev["last_vendor"] or "-",
            dev["last_device_type"],
            dev["first_seen"],
            str(dev["seen_count"]),
        )
    console.print(table)
    db.close()


@app.command()
def export(
    format: str = typer.Option("csv", help="Output format (csv, json)"),
    output: Path = typer.Option("history_export", help="Output filename without extension"),
    db_path: str = typer.Option("scan_history.db", help="Path to SQLite database"),
):
    """
    Export all known devices from the database to CSV or JSON.
    """
    from network_inventory.storage.database import ScanDatabase
    from network_inventory.models import DeviceRecord
    
    db = ScanDatabase(db_path)
    db.open()
    devices_data = db.get_all_devices()
    db.close()

    if not devices_data:
        console.print("[yellow]No data to export.[/yellow]")
        return

    # Mock a ScanResult for the exporters
    from network_inventory.models import ScanResult
    mock_result = ScanResult(target="Database Export", started_at="N/A")
    for d in devices_data:
        mock_result.devices.append(DeviceRecord(
            ip_address=d["last_ip"] or "Unknown",
            mac_address=d["mac"],
            vendor=d["last_vendor"],
            hostname=d["last_hostname"],
            device_type=d["last_device_type"],
            os_family=d["last_os_family"],
            ipv6_address=d["last_ipv6"]
        ))

    if format.lower() == "csv":
        export_csv(mock_result, output.with_suffix(".csv"))
        console.print(f"Exported to [cyan]{output.with_suffix('.csv')}[/cyan]")
    elif format.lower() == "json":
        export_json(mock_result, output.with_suffix(".json"))
        console.print(f"Exported to [cyan]{output.with_suffix('.json')}[/cyan]")
    else:
        console.print(f"[red]Unsupported format: {format}[/red]")


@app.command()
def map(
    db_path: str = typer.Option("scan_history.db", help="Path to SQLite database"),
    output: Path = typer.Option("network_map.mmd", help="Output Mermaid file"),
):
    """
    Generate a Mermaid topology map from the latest scan in the database.
    """
    from network_inventory.storage.database import ScanDatabase
    from network_inventory.models import ScanResult, DeviceRecord
    
    db = ScanDatabase(db_path)
    db.open()
    
    # Get the latest scan to get the real target CIDR
    last_scan_id = db.get_last_scan_id()
    if not last_scan_id:
        console.print("[yellow]No scans found in database. Run a scan first.[/yellow]")
        db.close()
        return

    # Fetch devices and target
    devices_data = db.get_all_devices()
    
    # Heuristic: Pull target from the latest scan entry in the 'scans' table
    scan_row = db._conn.execute("SELECT target FROM scans WHERE id = ?", (last_scan_id,)).fetchone()
    target_cidr = scan_row["target"] if scan_row else "Unknown Network"
    
    mock_result = ScanResult(target=target_cidr, started_at="N/A")
    for d in devices_data:
        mock_result.devices.append(DeviceRecord(
            ip_address=d["last_ip"] or "Unknown",
            mac_address=d["mac"],
            hostname=d["last_hostname"],
            device_type=d["last_device_type"]
        ))
    db.close()

    TopologyExporter.save_mermaid(mock_result, output)
    console.print(f"Topology map generated for [bold cyan]{target_cidr}[/bold cyan]: [green]{output}[/green]")
    console.print("[dim]Tip: Copy the content of this file to https://mermaid.live to see the graph.[/dim]")


@app.command()
def diff(
    scan_a: str = typer.Argument(None, help="First scan ID (default: second-last)"),
    scan_b: str = typer.Argument(None, help="Second scan ID (default: last)"),
    db_path: str = typer.Option("scan_history.db", help="Path to SQLite database"),
):
    """
    Compare two scans to show new, removed, and changed devices.
    """
    from network_inventory.storage.database import ScanDatabase

    db = ScanDatabase(db_path)
    db.open()

    scans = db.get_scan_ids(limit=2)
    if len(scans) < 2:
        console.print("[yellow]Need at least 2 scans in the database.[/yellow]")
        db.close()
        return

    scan_a = scan_a or scans[1]["id"]
    scan_b = scan_b or scans[0]["id"]

    result = db.diff_scans(scan_a, scan_b)
    db.close()

    console.print("\n[bold cyan]Scan Diff[/bold cyan]")
    console.print(f"  Scan A: [dim]{scan_a[:8]}...[/dim]")
    console.print(f"  Scan B: [dim]{scan_b[:8]}...[/dim]\n")

    if result["new"]:
        console.print(f"[bold green]New Devices ({len(result['new'])}):[/bold green]")
        for d in result["new"]:
            mac = d.get("mac", "")[:17]
            console.print(f"  [+] [green]{d['ip_address']:<15}[/] {mac} {d.get('hostname') or ''}")
    else:
        console.print("[dim]No new devices.[/dim]")

    if result["removed"]:
        console.print(f"\n[bold red]Removed Devices ({len(result['removed'])}):[/bold red]")
        for d in result["removed"]:
            mac = d.get("mac", "")[:17]
            console.print(f"  [-] [red]{d['ip_address']:<15}[/] {mac} {d.get('hostname') or ''}")
    else:
        console.print("\n[dim]No removed devices.[/dim]")

    if result["changed"]:
        console.print(f"\n[bold yellow]Changed Devices ({len(result['changed'])}):[/bold yellow]")
        for c in result["changed"]:
            a, b = c["before"], c["after"]
            mac = a.get("mac", "")[:17]
            console.print(f"  [~] [yellow]{mac}[/]")
            for field in ("ip_address", "hostname", "device_type", "vendor"):
                va = a.get(field) or "-"
                vb = b.get(field) or "-"
                if va != vb:
                    console.print(f"      {field}: [red]{va}[/] → [green]{vb}[/]")
    else:
        console.print("[dim]No changed devices.[/dim]")


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", help="Bind address"),
    port: int = typer.Option(8080, help="Port number"),
    db_path: str = typer.Option("scan_history.db", help="Path to SQLite database"),
):
    """
    Start a web dashboard to browse scan results.
    """
    from network_inventory.exporters.web_server import serve as _serve

    console.print("[bold cyan]Network Inventory Web UI[/bold cyan]")
    _serve(db_path, host, port)


@app.command()
def init_config():
    """
    Generate a default config.yaml file.
    """
    path = ConfigManager.get_default_path()
    if path.exists():
        if not typer.confirm(f"{path} already exists. Overwrite?"):
            return
    
    ConfigManager(path).save(AppConfig())
    console.print(f"[green]Created default configuration at {path}[/green]")


def main():
    app()


if __name__ == "__main__":
    main()
