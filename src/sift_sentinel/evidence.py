"""Evidence hashing and manifest generation."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Dict

from .case import CaseConfig
from .policies import EvidencePolicy


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_manifest(case: CaseConfig, policy: EvidencePolicy) -> Dict[str, Any]:
    artifacts = {}
    for name, artifact_path in sorted(case.artifacts.items()):
        path = policy.assert_readable_evidence(artifact_path)
        stat = path.stat()
        artifacts[name] = {
            "path": str(path),
            "size_bytes": stat.st_size,
            "sha256": sha256_file(path),
        }
    return {
        "case_id": case.case_id,
        "title": case.title,
        "evidence_root": str(case.evidence_root),
        "artifact_count": len(artifacts),
        "artifacts": artifacts,
    }

