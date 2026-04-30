"""Safe subprocess runner for SIFT command wrappers.

The demo case uses parsed fixture artifacts, but the same policy is used when
SIFT tools are available. Commands are arrays, never shell strings, and every
declared read/write path is checked before execution.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from .policies import EvidencePolicy, PolicyViolation


@dataclass(frozen=True)
class CommandResult:
    argv: List[str]
    returncode: int
    stdout: str
    stderr: str


class SafeSubprocessRunner:
    def __init__(self, policy: EvidencePolicy, allowed_binaries: Iterable[str], timeout_seconds: int = 120):
        self.policy = policy
        self.allowed_binaries = set(allowed_binaries)
        self.timeout_seconds = timeout_seconds

    def run(
        self,
        argv: List[str],
        *,
        read_paths: Optional[Iterable[Path]] = None,
        write_paths: Optional[Iterable[Path]] = None,
        env: Optional[Dict[str, str]] = None,
    ) -> CommandResult:
        if not argv:
            raise PolicyViolation("Refusing to execute an empty command")
        binary = Path(argv[0]).name
        if binary not in self.allowed_binaries and argv[0] not in self.allowed_binaries:
            raise PolicyViolation(f"Binary is not in the SIFT Sentinel allowlist: {argv[0]}")

        for path in read_paths or []:
            self.policy.assert_readable_evidence(path)
        for path in write_paths or []:
            self.policy.assert_output_path(path)

        completed = subprocess.run(
            argv,
            check=False,
            capture_output=True,
            text=True,
            timeout=self.timeout_seconds,
            env=env,
        )
        return CommandResult(
            argv=argv,
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )

