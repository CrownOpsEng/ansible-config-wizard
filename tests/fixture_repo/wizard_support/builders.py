from __future__ import annotations

from typing import Any


def build_sample_context(raw: dict[str, Any]) -> dict[str, Any]:
    data = dict(raw)
    data["derived_domain"] = f"ops.{data['base_domain']}"
    return data
