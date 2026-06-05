from __future__ import annotations

import json
from pathlib import Path

from network_inventory.models import ScanResult


def export_json(result: ScanResult, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(result.to_dict(), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
