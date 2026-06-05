from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def _load_package() -> None:
    package_dir = Path(__file__).resolve().with_name("network_inventory")
    spec = importlib.util.spec_from_file_location(
        "network_inventory",
        package_dir / "__init__.py",
        submodule_search_locations=[str(package_dir)],
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("Cannot load network_inventory package")
    module = importlib.util.module_from_spec(spec)
    sys.modules["network_inventory"] = module
    spec.loader.exec_module(module)


def main() -> None:
    _load_package()
    from network_inventory.main import main as package_main

    package_main()


if __name__ == "__main__":
    main()

