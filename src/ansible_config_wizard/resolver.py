from __future__ import annotations

import importlib
import sys
from pathlib import Path
from typing import Any, Callable


def resolve_builder(builder_ref: str | None, repo_root: Path, profile_root: Path) -> Callable[[dict[str, Any]], dict[str, Any]]:
    if not builder_ref:
        return lambda raw: raw

    module_name, separator, attr_name = builder_ref.partition(":")
    if not separator or not module_name or not attr_name:
        raise ValueError(f"Invalid builder reference: {builder_ref}")

    search_paths = [str(repo_root), str(profile_root)]
    for entry in reversed(search_paths):
        if entry not in sys.path:
            sys.path.insert(0, entry)

    module = importlib.import_module(module_name)
    builder = getattr(module, attr_name)
    if not callable(builder):
        raise TypeError(f"Builder is not callable: {builder_ref}")
    return builder
