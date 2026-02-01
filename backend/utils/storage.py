from __future__ import annotations

import os
from pathlib import Path


def safe_base_dir() -> str:
    """
    Base directory for Educator artifacts.
    Defaults to ./storage inside backend project.

    If STORAGE_BASE_DIR is provided, we use it (resolved).
    """
    base = os.getenv("STORAGE_BASE_DIR", "")
    if base.strip():
        p = Path(base).expanduser().resolve()
    else:
        # backend/utils/storage.py -> backend/
        backend_dir = Path(__file__).resolve().parent.parent
        p = (backend_dir / "storage").resolve()
    return str(p)


def ensure_dirs(base_dir: str) -> None:
    Path(base_dir).mkdir(parents=True, exist_ok=True)
    (Path(base_dir) / "audio").mkdir(parents=True, exist_ok=True)


def audio_path(base_dir: str, filename: str) -> str:
    return str((Path(base_dir) / "audio" / filename).resolve())
