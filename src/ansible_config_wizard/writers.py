from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def backup_existing(path: Path) -> Path | None:
    if not path.exists():
        return None
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    backup = path.with_name(f"{path.name}.bak-{stamp}")
    shutil.copy2(path, backup)
    return backup


def atomic_write(path: Path, content: str, mode: int) -> None:
    ensure_parent(path)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False, encoding="utf-8") as handle:
        handle.write(content)
        temp_path = Path(handle.name)
    temp_path.chmod(mode)
    temp_path.replace(path)


def secure_delete(path: Path) -> None:
    if not path.exists():
        return

    if shutil.which("shred") and path.is_file():
        result = subprocess.run(
            ["shred", "--force", "--remove", "--zero", "--iterations=3", str(path)],
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            return

    if path.is_file():
        size = path.stat().st_size
        with path.open("r+b") as handle:
            if size:
                handle.seek(0)
                handle.write(os.urandom(size))
                handle.flush()
                os.fsync(handle.fileno())
                handle.seek(0)
                handle.write(b"\x00" * size)
                handle.flush()
                os.fsync(handle.fileno())
        path.unlink(missing_ok=True)
        return

    if path.is_dir():
        shutil.rmtree(path)
