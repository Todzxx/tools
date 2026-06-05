from __future__ import annotations

from typing import Any

from rich.console import Console, Group
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.text import Text


class ProgressManager:
    """Professional progress manager for network scanning."""

    def __init__(self) -> None:
        self._console = Console()
        self._stages: dict[str, Any] = {}
        self._device_count = 0
        self._live: Any = None

        # Overall progress
        self._overall = Progress(
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(bar_width=40),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
        )
        self._overall_task = self._overall.add_task("Total Progress", total=100)

    def add_stage(self, key: str, label: str, total: int = 0) -> None:
        has_bar = total > 0
        p = Progress(
            SpinnerColumn(spinner_name="line"),
            TextColumn("[white]{task.description}"),
            BarColumn(bar_width=30) if has_bar else TextColumn(""),
            TextColumn("[dim]{task.completed}/{task.total}[/]")
            if has_bar
            else TextColumn(""),
            TextColumn("[green]{task.fields[info]}[/]"),
            TextColumn("[dim green]{task.fields[detail]}[/]"),
        )
        task_id = p.add_task(
            label, total=total if has_bar else None, info="", detail=""
        )
        self._stages[key] = {"progress": p, "task_id": task_id, "label": label}
        self._update_overall()

    def update_progress(self, key: str, advance: int = 1) -> None:
        if key in self._stages:
            s = self._stages[key]
            s["progress"].update(s["task_id"], advance=advance)
            self._refresh()

    def set_info(self, key: str, info: str) -> None:
        if key in self._stages:
            s = self._stages[key]
            s["progress"].update(s["task_id"], info=info)
            self._refresh()

    def set_detail(self, key: str, detail: str) -> None:
        if key in self._stages:
            s = self._stages[key]
            s["progress"].update(s["task_id"], detail=detail)
            self._refresh()

    def finish_stage(self, key: str) -> None:
        if key in self._stages:
            s = self._stages[key]
            task = s["progress"].tasks[s["task_id"]]
            kwargs: dict[str, Any] = {"description": f"[bold green]✓[/] {s['label']}"}
            if task.total is not None:
                kwargs["completed"] = task.total
            s["progress"].update(s["task_id"], **kwargs)
            self._update_overall()
            self._refresh()

    def set_device_count(self, count: int) -> None:
        self._device_count = count
        self._refresh()

    def _refresh(self) -> None:
        if self._live:
            self._live.update(self.get_renderable())

    def _update_overall(self) -> None:
        completed = sum(
            1
            for s in self._stages.values()
            if "[bold green]✓[/]" in s["progress"].tasks[s["task_id"]].description
        )
        total = max(len(self._stages), 1)
        self._overall.update(
            self._overall_task, completed=int((completed / total) * 100)
        )

    def get_renderable(self) -> Panel:
        group_items: list[Any] = [self._overall]

        # Initial stages if none added yet
        if not self._stages:
            # Placeholder stages to show structure
            pass

        for s in self._stages.values():
            group_items.append(s["progress"])

        footer = Text(
            f"[*] {self._device_count} devices discovered so far...", style="bold cyan"
        )
        group_items.append(footer)

        return Panel(
            Group(*group_items),
            title="[bold yellow]Network Inventory Progress[/]",
            border_style="blue",
            padding=(1, 2),
        )
