from __future__ import annotations

import ipaddress
from pathlib import Path
from network_inventory.models import ScanResult, DeviceRecord


class TopologyExporter:
    """Generates advanced visual network topology maps in Mermaid format."""

    @staticmethod
    def generate_mermaid(result: ScanResult) -> str:
        """
        Creates a sophisticated Mermaid diagram with subgraphs and color-coded device types.
        """
        lines = ["graph TD"]

        # 1. Professional Color Scheme
        lines.append("    %% Color Scheme Definitions")
        lines.append(
            "    classDef gateway fill:#f96,stroke:#333,stroke-width:3px,color:#000;"
        )
        lines.append(
            "    classDef laptop fill:#dfd,stroke:#2e7d32,stroke-width:1px,color:#000;"
        )
        lines.append(
            "    classDef smartphone fill:#e1f5fe,stroke:#0288d1,stroke-width:1px,color:#000;"
        )
        lines.append(
            "    classDef printer fill:#fff9c4,stroke:#fbc02d,stroke-width:1px,color:#000;"
        )
        lines.append(
            "    classDef cctv fill:#ffcdd2,stroke:#d32f2f,stroke-width:1px,color:#000;"
        )
        lines.append(
            "    classDef server fill:#e1bee7,stroke:#7b1fa2,stroke-width:1px,color:#000;"
        )
        lines.append(
            "    classDef unknown fill:#f5f5f5,stroke:#9e9e9e,stroke-width:1px,color:#000;"
        )

        # 2. Identify Gateway
        gateway_ip = None
        try:
            network = ipaddress.ip_network(result.target, strict=False)
            gateway_ip = str(next(network.hosts()))
        except Exception:
            pass

        # 3. Categorize devices for subgraphs
        categories: dict[str, list[DeviceRecord]] = {
            "Network Infrastructure": [],
            "Computers & Laptops": [],
            "Mobile Devices": [],
            "Printers": [],
            "Smart Home & IoT": [],
            "Others": [],
        }

        for dev in result.devices:
            dtype = dev.device_type
            if dtype == "Router" or dev.ip_address == gateway_ip:
                categories["Network Infrastructure"].append(dev)
            elif dtype in ["Laptop", "Desktop", "Windows PC", "Mac"]:
                categories["Computers & Laptops"].append(dev)
            elif dtype in ["Smartphone", "Android", "iPhone"]:
                categories["Mobile Devices"].append(dev)
            elif dtype == "Printer":
                categories["Printers"].append(dev)
            elif dtype in ["IoT", "Smart TV", "CCTV", "NAS", "Plex Server"]:
                categories["Smart Home & IoT"].append(dev)
            else:
                categories["Others"].append(dev)

        # 4. Generate Subgraphs
        for cat_name, devs in categories.items():
            if not devs:
                continue

            lines.append(f"\n    subgraph {cat_name.replace(' ', '_')} [ {cat_name} ]")
            for dev in devs:
                node_id = dev.ip_address.replace(".", "_")
                name = (
                    dev.hostname
                    if dev.hostname and dev.hostname != "-"
                    else dev.ip_address
                )
                label = (
                    f"<b>{name}</b><br/>{dev.ip_address}<br/><i>{dev.vendor or ''}</i>"
                )

                # Assign Class
                cls = "unknown"
                dtype = dev.device_type
                if dtype == "Router" or dev.ip_address == gateway_ip:
                    cls = "gateway"
                elif dtype in ["Laptop", "Desktop", "Windows PC", "Mac"]:
                    cls = "laptop"
                elif dtype in ["Smartphone", "Android", "iPhone"]:
                    cls = "smartphone"
                elif dtype == "Printer":
                    cls = "printer"
                elif dtype in ["CCTV"]:
                    cls = "cctv"
                elif dtype in ["NAS", "Plex Server"]:
                    cls = "server"

                lines.append(f'        {node_id}["{label}"]::: {cls}')
            lines.append("    end")

        # 5. Connect all to Gateway (Hub & Spoke)
        if gateway_ip:
            gw_id = gateway_ip.replace(".", "_")
            for dev in result.devices:
                if dev.ip_address != gateway_ip:
                    node_id = dev.ip_address.replace(".", "_")
                    lines.append(f"    {gw_id} --- {node_id}")

        return "\n".join(lines)

    @staticmethod
    def save_mermaid(result: ScanResult, output_path: Path):
        content = TopologyExporter.generate_mermaid(result)
        output_path.write_text(content, encoding="utf-8")
