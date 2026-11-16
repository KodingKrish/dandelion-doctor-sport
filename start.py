#!/usr/bin/env python3
"""
dandelion-doctor — one-command launcher.

Run this with just:   python start.py
(or double-click it on Windows once Python is associated with .py files)

What it does, in order:
  1. Checks the Python version (3.11+ required).
  2. Checks whether dandelion-doctor's dependencies are installed; if not,
     offers to install them with pip (editable install, so code edits take
     effect immediately without reinstalling).
  3. Builds the 10,560-fix catalog if it hasn't been built yet.
  4. Launches the Textual TUI. If Textual isn't installed and the person
     declines installing it, falls back to a tiny text menu that drives the
     existing CLI commands instead.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
MIN_PYTHON = (3, 11)


def fail(message: str) -> None:
    print(f"\n[ERROR] {message}\n")
    sys.exit(1)


def check_python_version() -> None:
    if sys.version_info < MIN_PYTHON:
        fail(
            f"Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+ is required, "
            f"found {sys.version_info.major}.{sys.version_info.minor}. "
            "Install a newer Python from https://www.python.org/downloads/ and try again."
        )


def ask_yes_no(prompt: str, default_yes: bool = True) -> bool:
    suffix = "[Y/n]" if default_yes else "[y/N]"
    try:
        answer = input(f"{prompt} {suffix} ").strip().lower()
    except EOFError:
        return default_yes
    if not answer:
        return default_yes
    return answer.startswith("y")


def pip_install(extras: str) -> None:
    print(f"\nInstalling dandelion-doctor (extras: {extras})... this can take a minute.\n")
    cmd = [sys.executable, "-m", "pip", "install", "-e", f".[{extras}]"]
    result = subprocess.run(cmd, cwd=REPO_ROOT)
    if result.returncode != 0:
        fail(
            "pip install failed. If you're on a system that blocks global installs, try:\n"
            f"  {sys.executable} -m pip install -e \".[{extras}]\" --break-system-packages\n"
            "or create a virtual environment first:\n"
            "  python -m venv .venv && .venv\\Scripts\\activate   (Windows)\n"
            "  python -m venv .venv && source .venv/bin/activate (macOS/Linux)"
        )


def ensure_dependencies(need_tui: bool) -> bool:
    """Returns True if the TUI's dependencies (textual) are available."""
    try:
        import dandelion_doctor  # noqa: F401
        core_installed = True
    except ImportError:
        core_installed = False

    try:
        import textual  # noqa: F401
        tui_installed = True
    except ImportError:
        tui_installed = False

    if core_installed and (tui_installed or not need_tui):
        return tui_installed

    if not core_installed:
        print("dandelion-doctor's core dependencies aren't installed yet.")
        extras = "dev,tui" if ask_yes_no("Install core + TUI dependencies now?", default_yes=True) else None
        if extras is None:
            if ask_yes_no("Install core dependencies only (CLI-only, no TUI)?", default_yes=True):
                extras = "dev"
            else:
                fail("Cannot continue without dandelion-doctor's core dependencies installed.")
        pip_install(extras)
        tui_installed = "tui" in extras
    elif need_tui and not tui_installed:
        if ask_yes_no("The TUI needs the 'textual' package, which isn't installed. Install it now?", default_yes=True):
            pip_install("tui")
            tui_installed = True

    return tui_installed


def ensure_catalog_built() -> None:
    db_path = REPO_ROOT / "assets" / "catalog" / "fixes_10560.db"
    if db_path.exists():
        return
    print("Fix catalog not found — building it now (one-time, a few seconds)...")
    result = subprocess.run([sys.executable, "scripts/build_fix_catalog.py"], cwd=REPO_ROOT)
    if result.returncode != 0:
        fail("Failed to build the fix catalog. See the error above.")


def launch_tui() -> None:
    from dandelion_doctor.ui.tui import run
    run()


def launch_cli_menu() -> None:
    """Minimal fallback menu for when Textual isn't installed."""
    import typer

    from dandelion_doctor.ui import cli as cli_module

    menu = """
dandelion-doctor — CLI menu (TUI not installed)
  1) status      — device lock / Golden Vault status
  2) search      — full-text search the fix catalog
  3) diagnose    — read-only diagnosis from captured dmesg/logcat
  4) preflight   — run the Section 13.1 pre-flight checklist
  q) quit
"""
    while True:
        print(menu)
        choice = input("Choose an option: ").strip().lower()
        if choice in ("q", "quit", "exit"):
            break
        elif choice == "1":
            cli_module.status()
        elif choice == "2":
            query = input("Search query: ").strip()
            if query:
                cli_module.search(query)
        elif choice == "3":
            dmesg = input("Path to captured dmesg file (blank to skip): ").strip()
            brom_error = input("BROM/SPFT error code (blank to skip): ").strip()
            cli_module.diagnose(
                dmesg=Path(dmesg) if dmesg else None,
                logcat=None,
                brom_error=brom_error or None,
            )
        elif choice == "4":
            serial = input("Connected device serial (blank to skip): ").strip()
            battery = input("Battery mV (blank to skip): ").strip()
            cli_module.preflight(
                battery_mv=int(battery) if battery.isdigit() else None,
                serialno=serial or None,
            )
        else:
            print("Not a recognized option.")


def main() -> None:
    print("=" * 60)
    print("  dandelion-doctor — Redmi 9A Sport (M2006C3LI) toolkit")
    print("=" * 60)

    check_python_version()
    tui_available = ensure_dependencies(need_tui=True)
    ensure_catalog_built()

    if tui_available:
        print("\nLaunching the TUI... (press 'q' inside it to quit)\n")
        launch_tui()
    else:
        print("\nContinuing without the TUI.\n")
        launch_cli_menu()


if __name__ == "__main__":
    main()
