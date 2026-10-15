"""Resolved data roots and safe path validation."""

from __future__ import annotations

import os
from pathlib import Path


def project_root() -> Path:
    return Path(__file__).resolve().parent.parent


def data_root() -> Path:
    raw = os.environ.get("SECUREAUDIT_DATA_ROOT", "").strip()
    if raw:
        return Path(raw).expanduser().resolve()
    return (project_root() / "sample_data").resolve()


def allow_any_path() -> bool:
    return os.environ.get("SECUREAUDIT_ALLOW_ANY_PATH", "").strip() in ("1", "true", "yes")


def resolve_under_data_root(rel_or_abs: str) -> Path:
    p = Path(rel_or_abs).expanduser()
    if not p.is_absolute():
        p = (data_root() / p).resolve()
    else:
        p = p.resolve()
    if not allow_any_path():
        root = data_root()
        try:
            p.relative_to(root)
        except ValueError as e:
            raise PermissionError(
                f"Path {p} is outside SECUREAUDIT_DATA_ROOT ({root}). "
                "Set SECUREAUDIT_ALLOW_ANY_PATH=1 to override (use with care)."
            ) from e
    if not p.is_file():
        raise FileNotFoundError(f"Not a file: {p}")
    return p
