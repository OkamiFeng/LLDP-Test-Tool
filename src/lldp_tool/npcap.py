from __future__ import annotations

import ctypes
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


@dataclass(frozen=True)
class NpcapStatus:
    installed: bool
    driver_running: bool
    message: str


ServiceLookup = Callable[[], dict[str, str]]


def query_npcap_services() -> dict[str, str]:
    states: dict[str, str] = {}
    for service_name in ("npcap", "npf"):
        result = subprocess.run(
            ["sc.exe", "query", service_name],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            continue
        output = result.stdout.upper()
        if "RUNNING" in output:
            states[service_name] = "Running"
        elif "STOPPED" in output:
            states[service_name] = "Stopped"
        else:
            states[service_name] = "Unknown"
    return states


def detect_npcap_status(
    system_root: Path | str | None = None,
    service_lookup: ServiceLookup | None = None,
) -> NpcapStatus:
    root = Path(system_root or os.environ.get("SystemRoot", r"C:\Windows"))
    npcap_dir = root / "System32" / "Npcap"
    installed = (npcap_dir / "wpcap.dll").exists() and (npcap_dir / "Packet.dll").exists()

    services = service_lookup() if service_lookup is not None else query_npcap_services()
    driver_running = any(
        services.get(name, "").lower() == "running" for name in ("npcap", "npf")
    )

    if installed and driver_running:
        message = "Npcap は利用可能です。"
    elif installed:
        message = "Npcap は見つかりましたが、ドライバーが起動していません。"
    else:
        message = "Npcap が見つかりません。初回設定を実行してください。"

    return NpcapStatus(
        installed=installed,
        driver_running=driver_running,
        message=message,
    )


def application_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[2]


def find_bundled_npcap_installer(base_dir: Path | str | None = None) -> Path | None:
    root = Path(base_dir) if base_dir is not None else application_dir()
    search_dirs = [root / "drivers", root]
    for directory in search_dirs:
        if not directory.exists():
            continue
        candidates = sorted(directory.glob("npcap-*.exe"), reverse=True)
        if candidates:
            return candidates[0]
    return None


def is_running_as_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def launch_npcap_installer(installer_path: Path) -> None:
    path = Path(installer_path)
    if not path.exists():
        raise FileNotFoundError(f"Npcap installer not found: {path}")

    if os.name == "nt":
        result = ctypes.windll.shell32.ShellExecuteW(
            None,
            "runas",
            str(path),
            "",
            str(path.parent),
            1,
        )
        if result <= 32:
            raise OSError(f"Npcap installer launch failed: {result}")
        return

    subprocess.Popen([str(path)], cwd=str(path.parent))
