from __future__ import annotations

import os
from dotenv import load_dotenv


def load_env() -> None:
    """
    Loads environment variables from .env if present.
    Safe to call multiple times.
    """
    load_dotenv(override=False)


def env_str(key: str, default: str = "") -> str:
    v = os.getenv(key)
    return v if v is not None else default


def env_bool(key: str, default: bool = False) -> bool:
    v = os.getenv(key)
    if v is None:
        return default
    v = v.strip().lower()
    return v in ("1", "true", "yes", "y", "on")


def env_int(key: str, default: int = 0) -> int:
    v = os.getenv(key)
    if v is None:
        return default
    try:
        return int(v.strip())
    except ValueError:
        return default
