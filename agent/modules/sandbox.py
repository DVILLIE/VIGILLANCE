"""Windows Sandbox "Open unfamiliar" — Pro, Enterprise, and Education only.

Microsoft Learn (Windows Sandbox overview, reviewed 2026-09-29) lists Pro,
Enterprise, Pro Education, and Education. Home is not supported. Networking is
on unless a ``.wsb`` file sets ``<Networking>Disable</Networking>``. Mapped
folders are writable unless ``<ReadOnly>true</ReadOnly>``. The unknown-file
sample also disables vGPU.

This module does not start Windows Defender Application Guard (deprecated,
removed starting Windows 11 24H2) and does not start a Hyper-V virtual machine.
A normal desktop process is not Windows Sandbox. Guest networking stays
UNKNOWN unless a probe reports it. Group Policy can override a ``.wsb`` file;
this version does not read that policy.
"""

from __future__ import annotations

import os
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Callable

from agent.policy.dual import require_cortex_mutate
from agent.utils import IS_WINDOWS

SANDBOX_FOLDER = r"C:\Users\WDAGUtilityAccount\Desktop\Unfamiliar"
SANDBOX_EXE_NAME = "windowssandbox.exe"

Launch = Callable[[list[str]], int]
Exists = Callable[[str], bool]
Probe = Callable[[str], str | None]

_CONTROLS = (
    "Smart App Control (SAC): probe only. Clean-install eligibility is not inferred. This checklist does not turn it on.",
    "Attack surface reduction (ASR): available on Windows Home when Defender Antivirus is active. This checklist does not change ASR rules.",
    "Controlled folder access (CFA): a modification shield when enabled. DVielle does not claim it prevents reading or exfiltration.",
    "Windows Firewall: included on Windows Home. This checklist does not add a rule and does not stop the firewall service.",
)
_NOT_SANDBOX = (
    "Windows Defender Application Guard is deprecated and was removed starting in Windows 11 version 24H2. It is not used.",
    "Client Hyper-V is not available on Windows Home and is not Windows Sandbox.",
)
HOME_LINE = "Windows Sandbox is not supported on Windows Home. A normal desktop window is not Windows Sandbox."

ASSUMPTIONS = (
    "Windows Sandbox is documented for Pro, Enterprise, and Education, not for Home.",
    "Networking is on by default until the .wsb file sets Disable.",
    "The mapped folder is read-only. The file is still opened inside the sandbox.",
    "Guest networking is UNKNOWN unless a probe reports it.",
    "Group Policy can override a .wsb setting. This version does not read that policy.",
)


def _exe_name(path: str) -> str:
    """Last path segment. Backslashes count on every host, not only on Windows."""
    normalized = str(path or "").replace("\\", "/").rstrip("/")
    return normalized.rsplit("/", 1)[-1].lower()


def default_sandbox_launch(argv: list[str]) -> int:
    """Start WindowsSandbox.exe. Any other host executable is refused."""
    if len(argv) != 2 or _exe_name(argv[0]) != SANDBOX_EXE_NAME:
        return 127
    if not IS_WINDOWS:
        return 127
    import subprocess

    process = subprocess.Popen(argv, close_fds=True)
    return 0 if process.pid else 1


def probe_sandbox_feature() -> bool | None:
    """True when WindowsSandbox.exe is on disk. Absence is False. Non-Windows is None."""
    if not IS_WINDOWS:
        return None
    root = os.environ.get("SystemRoot", r"C:\Windows")
    return Path(root, "System32", "WindowsSandbox.exe").is_file()


def _base(offer: str, message: str, checklist: tuple[str, ...] | list[str]) -> dict[str, Any]:
    return {
        "offer": offer,
        "running": False,
        "isolation": "none",
        "network_verification": "not_applicable",
        "checklist": list(checklist),
        "message": message,
        "assumptions": list(ASSUMPTIONS),
        "launched": False,
        "performed": False,
        "wsb": None,
        "substituted_product": False,
    }


def observe_sandbox(sku: str, *, feature_installed: bool | None) -> dict[str, Any]:
    """Edition offer only. Does not write a .wsb file and does not start a process."""
    if sku in {"Home", "NonWindows", "Server"}:
        checklist = _CONTROLS + ((HOME_LINE,) if sku == "Home" else ()) + _NOT_SANDBOX
        if sku == "Home":
            message = HOME_LINE + " SAC, ASR, CFA, and Firewall remain the checklist. Nothing was opened."
        elif sku == "Server":
            message = "Windows Sandbox is not claimed for Windows Server. Nothing was opened."
        else:
            message = "This host is not Windows. Windows Sandbox was not opened."
        return _base("UNAVAILABLE", message, checklist)
    if sku != "ProOrHigher":
        return _base(
            "UNKNOWN",
            "The Windows edition was not identified. Windows Sandbox was not opened.",
            _CONTROLS + _NOT_SANDBOX,
        )
    if feature_installed is None:
        return _base(
            "UNKNOWN",
            "This edition can support Windows Sandbox. Whether the optional feature is installed was not observed. Nothing was opened.",
            _CONTROLS,
        )
    if feature_installed is False:
        return _base(
            "LIMITED",
            "This edition supports Windows Sandbox. The optional feature is not installed. DVielle did not enable it and did not open a window.",
            _CONTROLS
            + (
                "Install the Windows Sandbox optional feature yourself if you want it. DVielle will not turn it on from this checklist.",
            )
            + _NOT_SANDBOX,
        )
    return _base(
        "READY",
        "Windows Sandbox can be started from a .wsb profile that disables networking and maps one read-only folder. Nothing was opened. A desktop window is not that sandbox.",
        _CONTROLS
        + (
            "The unfamiliar profile sets Networking to Disable and ReadOnly to true. Default sandbox networking stays on until that file is used.",
        )
        + _NOT_SANDBOX,
    )


def _windows_absolute(folder: str) -> bool:
    if len(folder) < 3 or folder[1] != ":":
        return False
    if not folder[0].isalpha() or folder[2] not in "\\/":
        return False
    if any(ord(char) < 32 or char in '<>"|?*' for char in folder):
        return False
    parts = folder.replace("/", "\\").split("\\")
    return ".." not in parts and "." not in parts[1:]


def _verify_wsb(text: str, host_folder: str) -> str | None:
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return "The sandbox profile was not valid XML."
    if root.tag != "Configuration":
        return "The sandbox profile was not a Windows Sandbox configuration."
    children = list(root)
    tags = [child.tag for child in children]
    if tags.count("Networking") != 1 or tags.count("MappedFolders") != 1:
        return "The sandbox profile did not have exactly one networking setting and one mapped folder."
    networking = root.findtext("Networking")
    if networking != "Disable":
        return "The sandbox profile did not disable networking."
    if root.findtext("VGpu") != "Disable":
        return "The sandbox profile did not disable vGPU."
    folder_parent = root.find("MappedFolders")
    folders = [] if folder_parent is None else list(folder_parent)
    if len(folders) != 1 or folders[0].tag != "MappedFolder":
        return "The sandbox profile did not map exactly one folder."
    mapped = folders[0]
    if mapped.findtext("HostFolder") != host_folder:
        return "The sandbox profile mapped a different folder."
    if mapped.findtext("SandboxFolder") != SANDBOX_FOLDER:
        return "The sandbox profile mapped the folder outside the unfamiliar desktop path."
    if (mapped.findtext("ReadOnly") or "").lower() != "true":
        return "The sandbox profile did not map the folder read-only."
    if root.findtext("ClipboardRedirection") != "Disable":
        return "The sandbox profile did not disable clipboard redirection."
    command = root.findtext("LogonCommand/Command")
    if command != f"explorer.exe {SANDBOX_FOLDER}":
        return "The sandbox profile logon command was not the unfamiliar folder."
    return None


def _profile(host_folder: str) -> str:
    root = ET.Element("Configuration")
    ET.SubElement(root, "VGpu").text = "Disable"
    ET.SubElement(root, "Networking").text = "Disable"
    ET.SubElement(root, "ClipboardRedirection").text = "Disable"
    folders = ET.SubElement(root, "MappedFolders")
    mapped = ET.SubElement(folders, "MappedFolder")
    ET.SubElement(mapped, "HostFolder").text = host_folder
    ET.SubElement(mapped, "SandboxFolder").text = SANDBOX_FOLDER
    ET.SubElement(mapped, "ReadOnly").text = "true"
    logon = ET.SubElement(root, "LogonCommand")
    ET.SubElement(logon, "Command").text = f"explorer.exe {SANDBOX_FOLDER}"
    return ET.tostring(root, encoding="unicode")


def open_unfamiliar(
    *,
    sku: str,
    host_folder: str,
    feature_installed: bool | None,
    sandbox_exe: str,
    folder_exists: Exists,
    launch: Launch,
    network_probe: Probe | None = None,
    wsb_dir: Path | None = None,
    read_only: bool = True,
) -> dict[str, Any]:
    """Write a disabled-network .wsb and start WindowsSandbox.exe only.

    Home, an unknown edition, a missing feature, a writable map, and any
    executable other than WindowsSandbox.exe do not start. The launch itself
    requires the dual-gate mutate context.
    """
    observed = observe_sandbox(sku, feature_installed=feature_installed if sku == "ProOrHigher" else feature_installed)
    if sku != "ProOrHigher" or observed["offer"] != "READY":
        observed["message"] = observed["message"] + " No sandbox process was started."
        return observed
    if read_only is not True:
        body = _base(
            "REFUSED",
            "Open unfamiliar maps one read-only folder. A writable map was refused. Nothing was started.",
            _CONTROLS,
        )
        body["offer"] = "REFUSED"
        return body
    if not isinstance(host_folder, str) or not _windows_absolute(host_folder):
        body = _base(
            "REFUSED",
            "The unfamiliar folder must be an absolute Windows path. Nothing was started.",
            (),
        )
        body["offer"] = "REFUSED"
        return body
    if not folder_exists(host_folder):
        body = _base("REFUSED", "That folder is not on this PC. Nothing was started.", ())
        body["offer"] = "REFUSED"
        return body
    exe_name = _exe_name(str(sandbox_exe or ""))
    if exe_name != SANDBOX_EXE_NAME:
        body = _base(
            "REFUSED",
            "DVielle only starts WindowsSandbox.exe with a .wsb profile. A normal desktop window is not Windows Sandbox. Nothing was started.",
            _NOT_SANDBOX,
        )
        body["offer"] = "REFUSED"
        return body
    require_cortex_mutate()
    directory = Path(wsb_dir) if wsb_dir is not None else Path(os.environ.get("TEMP", "."))
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "dvielle-unfamiliar.wsb"
    path.write_text(_profile(host_folder), encoding="utf-8")
    reread = path.read_text(encoding="utf-8")
    error = _verify_wsb(reread, host_folder)
    if error:
        body = _base("REFUSED", error + " Windows Sandbox was not started.", ())
        body["offer"] = "REFUSED"
        body["wsb"] = str(path)
        return body
    argv = [str(sandbox_exe), str(path)]
    if any(part.lower().endswith("explorer.exe") for part in argv):
        body = _base(
            "REFUSED",
            "The host command was not WindowsSandbox.exe. Nothing was started.",
            (),
        )
        body["offer"] = "REFUSED"
        return body
    code = launch(argv)
    if code != 0:
        body = _base(
            "REFUSED",
            "Windows Sandbox did not start. No desktop window was labeled as a sandbox.",
            (),
        )
        body["offer"] = "REFUSED"
        body["wsb"] = str(path)
        return body
    reported: str | None
    try:
        reported = None if network_probe is None else network_probe(str(path))
    except Exception:
        reported = None
    if reported == "disabled":
        message = (
            "Windows Sandbox was started from a profile that disables networking and maps one read-only folder. "
            "The network probe reported networking disabled. Group Policy override of .wsb settings was not read. "
            "This is not a claim that malware cannot leave the sandbox."
        )
        isolation = "VERIFIED"
        network = "verified"
        performed = True
    elif reported == "enabled":
        message = (
            "Windows Sandbox started, and the network probe reported that networking was not disabled. "
            "DVielle does not treat this session as a disabled-network sandbox. Close that window."
        )
        isolation = "REFUSED"
        network = "failed"
        performed = False
    else:
        message = (
            "Windows Sandbox was started from a profile that disables networking and maps one read-only folder. "
            "Guest networking was not observed, so this result is LIMITED. It is not a verified network-off claim."
        )
        isolation = "LIMITED"
        network = "UNKNOWN"
        performed = True
    return {
        "offer": observed["offer"],
        "running": True,
        "isolation": isolation,
        "network_verification": network,
        "checklist": list(observed["checklist"]),
        "message": message,
        "assumptions": list(ASSUMPTIONS),
        "launched": True,
        "performed": performed,
        "wsb": str(path),
        "substituted_product": False,
        "command": argv,
    }
