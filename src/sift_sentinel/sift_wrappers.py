"""Purpose-built SIFT command wrappers for real workstation execution."""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List

from .case import CaseConfig
from .runners import CommandResult, SafeSubprocessRunner


VOLATILITY_PLUGINS = {
    "windows.pslist",
    "windows.psscan",
    "windows.pstree",
    "windows.cmdline",
    "windows.netstat",
    "windows.netscan",
    "windows.malfind",
    "windows.svcscan",
    "windows.registry.hivelist",
    "windows.registry.printkey",
    "windows.filescan",
    "timeliner",
}


class SiftWrappers:
    """Narrow wrappers around SIFT tools.

    These are intentionally smaller than a shell. Each method validates plugin
    names, paths, and output locations before running an allowlisted binary.
    """

    def __init__(self, case: CaseConfig, runner: SafeSubprocessRunner):
        self.case = case
        self.runner = runner

    def volatility_json(self, image_artifact: str, plugin: str) -> CommandResult:
        if plugin not in VOLATILITY_PLUGINS:
            raise ValueError(f"Volatility plugin is not approved: {plugin}")
        image_path = self.case.artifact(image_artifact)
        argv = [
            "python3",
            "/opt/volatility3-2.20.0/vol.py",
            "-f",
            str(image_path),
            "-r",
            "json",
            plugin,
        ]
        return self.runner.run(argv, read_paths=[image_path])

    def evtxecmd_csv(self, evtx_dir_artifact: str, output_csv: Path) -> CommandResult:
        evtx_path = self.case.artifact(evtx_dir_artifact)
        argv = [
            "dotnet",
            "/opt/zimmermantools/EvtxeCmd/EvtxECmd.dll",
            "-d",
            str(evtx_path),
            "--csv",
            str(output_csv.parent),
            "--csvf",
            output_csv.name,
            "--maps",
            "/opt/zimmermantools/EvtxeCmd/Maps/",
        ]
        return self.runner.run(argv, read_paths=[evtx_path], write_paths=[output_csv])

    @staticmethod
    def default_allowed_binaries() -> List[str]:
        return ["python3", "dotnet", "fls", "icat", "mmls", "ewfverify", "yara"]

    @staticmethod
    def tool_contracts() -> Dict[str, Dict[str, str]]:
        return {
            "volatility_json": {
                "boundary": "read-only memory image input, allowlisted plugin, JSON renderer",
                "destructive_risk": "none exposed",
            },
            "evtxecmd_csv": {
                "boundary": "read-only event log input, CSV output below case output root",
                "destructive_risk": "none exposed",
            },
        }

