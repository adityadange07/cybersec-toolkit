#!/usr/bin/env python3
"""
Terminal UI for the CyberSec Toolkit.

Replaces the broken `main.py` rich menu (which referenced an undefined
`_execute_module`/`MODULE_CONFIG` dispatch). This UI dynamically discovers every
`BaseModule` subclass under `modules/` and runs it through `BaseModule.execute()`,
preserving the existing authorization, logging, and output-saving behavior.
"""
import importlib
import inspect
import json
import sys
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, IntPrompt
from rich import print as rprint

from config.settings import config
from core.base_module import BaseModule

console = Console()

# Human-friendly category labels (drawn from the original main.py menu).
CATEGORY_LABELS = {
    "recon": "🔍 Reconnaissance",
    "vuln_scanner": "⚠️  Vulnerability Scanning",
    "network": "🌐 Network Tools",
    "mobile": "📱 Mobile Analysis",
    "malware_analysis": "🦠 Malware Analysis",
    "forensics": "🔍 Forensics",
    "password": "🔑 Password Attacks",
    "defensive": "🛡️ Defense & Monitoring",
    "reporting": "📄 Reporting",
    "exploitation": "💥 Exploitation",
    "reverse_engineering": "🧬 Reverse Engineering",
}

# Modules that do not need a real host target (they use `target` as a mode/value).
NO_TARGET_MODULES = {
    "password": {"PasswordGenerator"},
}

# Common per-module option hints shown after a module is selected.
OPTION_HINTS = {
    "PortScanner": "Options: scan_type=tcp|syn, port_range=1-1024, ports=80,443",
    "ServiceEnumerator": "Options: ports=22,80,443, max_threads=10",
    "PasswordGenerator": "Options: mode=password|passphrase|pin|apikey|uuid|check, "
                          "length=20, count=5, check_value=<pwd>",
}


def discover_modules():
    """Import every module under ``modules/`` and return a list of
    ``(category, class_name, cls)`` tuples for all ``BaseModule`` subclasses."""
    base = Path(__file__).parent
    modules_dir = base / "modules"
    found = []
    for category_dir in sorted(modules_dir.iterdir()):
        if not category_dir.is_dir():
            continue
        category = category_dir.name
        for py_file in sorted(category_dir.glob("*.py")):
            if py_file.name.startswith("__"):
                continue
            module_name = f"modules.{category}.{py_file.stem}"
            try:
                mod = importlib.import_module(module_name)
            except Exception as e:  # a broken module should not kill the UI
                console.print(f"[dim]⚠️  Could not import {module_name}: {e}[/dim]")
                continue
            for name, obj in inspect.getmembers(mod, inspect.isclass):
                if issubclass(obj, BaseModule) and obj is not BaseModule:
                    if obj.__module__ == module_name:
                        found.append((category, name, obj))
    return found


def build_menu(modules):
    """Group discovered modules by category for display."""
    grouped = {}
    for category, name, cls in modules:
        grouped.setdefault(category, []).append((name, cls))
    return grouped


def display_banner():
    console.print(Panel(
        "[bold green]CyberSec Toolkit — Terminal UI[/bold green]\n"
        "[yellow]For Authorized Security Testing Only[/yellow]",
        border_style="cyan",
    ))


def display_disclaimer():
    response = Prompt.ask(
        "\n[bold red]🔒 Use this tool ethically and legally?[/bold red]",
        choices=["yes", "no"], default="no",
    )
    if response != "yes":
        console.print("[red]❌ You must agree to the terms to use this tool.[/red]")
        sys.exit(0)


def show_module_list(grouped):
    table = Table(title="Available Modules", border_style="blue")
    table.add_column("No.", style="cyan", width=4)
    table.add_column("Category", style="magenta")
    table.add_column("Module", style="green")
    index = 1
    flat = []
    for category in sorted(grouped):
        label = CATEGORY_LABELS.get(category, category)
        for name, cls in grouped[category]:
            table.add_row(str(index), label, name)
            flat.append((category, name, cls))
            index += 1
    console.print(table)
    return flat


def prompt_target(category, cls):
    if category in NO_TARGET_MODULES and cls.__name__ in NO_TARGET_MODULES[category]:
        return Prompt.ask("[cyan]🎯 Value / mode[/cyan]", default="password")
    return Prompt.ask("[cyan]🎯 Target (host, IP, domain, or file path)[/cyan]")


def prompt_options(cls):
    hints = OPTION_HINTS.get(cls.__name__)
    if hints:
        console.print(f"[dim]{hints}[/dim]")
    raw = Prompt.ask(
        "[cyan]⚙️  Extra options (key=value, comma-separated; blank for defaults)[/cyan]",
        default="",
    )
    options = {}
    for part in raw.split(","):
        part = part.strip()
        if not part or "=" not in part:
            continue
        key, val = part.split("=", 1)
        key, val = key.strip(), val.strip()
        # best-effort type coercion
        if val.isdigit():
            val = int(val)
        elif val.lower() in ("true", "false"):
            val = val.lower() == "true"
        options[key] = val
    return options


def run_selected(category, cls, index_label):
    target = prompt_target(category, cls)
    options = prompt_options(cls)

    # Authorization guard (inherited from BaseModule).
    instance = cls()
    if not instance.check_authorization(target):
        console.print("[yellow]⚠️  Authorization check failed; aborting.[/yellow]")
        return

    console.print(f"\n[bold cyan]▶ Running {cls.__name__} against {target}...[/bold cyan]")
    try:
        results = instance.execute(target, **options)
    except Exception as e:
        console.print(f"[red]❌ Error: {e}[/red]")
        return

    console.print(Panel(
        json.dumps(results, indent=2, default=str)[:4000],
        title=f"📊 {cls.__name__} Results",
        border_style="green",
    ))

    save = Prompt.ask(
        "[bold green]💾 Save results to JSON?[/bold green]",
        choices=["yes", "no"], default="yes",
    )
    if save == "yes":
        config.OUTPUT_DIR.mkdir(exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_file = config.OUTPUT_DIR / f"{cls.__name__}_{ts}.json"
        with open(out_file, "w") as f:
            json.dump(results, f, indent=2, default=str)
        console.print(f"[green]✅ Saved to {out_file}[/green]")


def main():
    display_banner()
    display_disclaimer()

    modules = discover_modules()
    grouped = build_menu(modules)

    if not modules:
        console.print("[red]❌ No modules discovered under modules/.[/red]")
        sys.exit(1)

    while True:
        flat = show_module_list(grouped)
        console.print("\n[dim]Enter a module number, or 0 to exit.[/dim]")
        try:
            choice = IntPrompt.ask("[bold cyan]🎯 Select module[/bold cyan]", default=0)
        except (KeyboardInterrupt, EOFError):
            console.print("\n[yellow]👋 Goodbye.[/yellow]")
            break

        if choice == 0:
            console.print("[green]👋 Thanks for using CyberSec Toolkit! Stay ethical! 🛡️[/green]")
            break
        if not (1 <= choice <= len(flat)):
            console.print(f"[red]❌ Invalid choice. Pick 1-{len(flat)} or 0.[/red]")
            continue

        category, name, cls = flat[choice - 1]
        run_selected(category, cls, choice)
        console.print()


if __name__ == "__main__":
    main()
