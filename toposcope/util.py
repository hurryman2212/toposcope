from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import Any

MISSING_VALUES = {"", "none", "unknown", "not specified", "to be filled by o.e.m."}


def root_join(root: Path, absolute_path: str | Path) -> Path:
    path = Path(absolute_path)
    if path.is_absolute():
        return root / path.relative_to("/")
    return root / path


def read_text(path: Path, *, max_bytes: int = 262_144) -> str | None:
    try:
        with path.open("rb") as file:
            data = file.read(max_bytes + 1)
    except (FileNotFoundError, PermissionError, IsADirectoryError, OSError):
        return None
    if len(data) > max_bytes:
        data = data[:max_bytes]
    return data.decode("utf-8", errors="replace").replace("\x00", "").strip()


def read_bytes(path: Path, *, max_bytes: int = 262_144) -> bytes | None:
    try:
        with path.open("rb") as file:
            data = file.read(max_bytes + 1)
    except (FileNotFoundError, PermissionError, IsADirectoryError, OSError):
        return None
    if len(data) > max_bytes:
        data = data[:max_bytes]
    return data


def read_first_line(path: Path) -> str | None:
    value = read_text(path, max_bytes=8192)
    if value is None:
        return None
    for line in value.splitlines():
        cleaned = line.strip()
        if cleaned:
            return cleaned
    return ""


def clean_value(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip()
    if cleaned.lower() in MISSING_VALUES:
        return None
    return cleaned


def read_clean(path: Path) -> str | None:
    return clean_value(read_first_line(path))


def read_int(path: Path, *, base: int = 10) -> int | None:
    value = read_first_line(path)
    if value is None:
        return None
    value = value.strip()
    if not value:
        return None
    try:
        return int(value, base=base)
    except ValueError:
        return None


def parse_int(value: str | None, *, base: int = 10) -> int | None:
    if value is None:
        return None
    try:
        return int(value.strip(), base=base)
    except (AttributeError, ValueError):
        return None


def parse_hex_id(value: str | None, *, width: int = 4) -> str | None:
    if value is None:
        return None
    cleaned = value.strip().lower()
    if cleaned.startswith("0x"):
        cleaned = cleaned[2:]
    if not cleaned:
        return None
    try:
        int(cleaned, 16)
    except ValueError:
        return None
    return cleaned.zfill(width)


def read_hex_id(path: Path, *, width: int = 4) -> str | None:
    return parse_hex_id(read_first_line(path), width=width)


def parse_cpu_list(value: str | None) -> list[int]:
    if not value:
        return []
    cpus: list[int] = []
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_text, end_text = part.split("-", 1)
            start = parse_int(start_text)
            end = parse_int(end_text)
            if start is None or end is None or end < start:
                continue
            cpus.extend(range(start, end + 1))
        else:
            cpu = parse_int(part)
            if cpu is not None:
                cpus.append(cpu)
    return sorted(set(cpus))


def parse_meminfo(path: Path) -> dict[str, int | str]:
    text = read_text(path)
    if text is None:
        return {}
    values: dict[str, int | str] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, raw = line.split(":", 1)
        pieces = raw.strip().split()
        if not pieces:
            continue
        number = parse_int(pieces[0])
        if number is None:
            values[key] = raw.strip()
            continue
        unit = pieces[1].lower() if len(pieces) > 1 else ""
        values[key] = number * 1024 if unit == "kb" else number
    return values


def readlink_name(path: Path) -> str | None:
    try:
        return path.resolve().name
    except (FileNotFoundError, OSError):
        return None


def readlink_target(path: Path) -> str | None:
    try:
        return str(path.resolve())
    except (FileNotFoundError, OSError):
        return None


def natural_key(text: str) -> list[tuple[int, int | str]]:
    parts: list[tuple[int, int | str]] = []
    current = ""
    number = ""
    for char in text:
        if char.isdigit():
            if current:
                parts.append((1, current))
                current = ""
            number += char
        else:
            if number:
                parts.append((0, int(number)))
                number = ""
            current += char
    if number:
        parts.append((0, int(number)))
    if current:
        parts.append((1, current))
    return parts


def sorted_paths(paths: Iterable[Path]) -> list[Path]:
    return sorted(paths, key=lambda path: natural_key(path.name))


def human_bytes(value: int | None) -> str | None:
    if value is None:
        return None
    units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"]
    size = float(value)
    for unit in units:
        if abs(size) < 1024.0 or unit == units[-1]:
            if unit == "B":
                return f"{int(size)} {unit}"
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{value} B"


def truthy_sysfs(value: str | None) -> bool | None:
    if value is None:
        return None
    cleaned = value.strip().lower()
    if cleaned in {"1", "y", "yes", "true", "enabled", "online"}:
        return True
    if cleaned in {"0", "n", "no", "false", "disabled", "offline"}:
        return False
    return None


def drop_none(value: Any) -> Any:
    if isinstance(value, dict):
        cleaned: dict[str, Any] = {}
        for key, item in value.items():
            dropped = drop_none(item)
            if dropped is not None and dropped != {} and dropped != []:
                cleaned[key] = dropped
        return cleaned
    if isinstance(value, list):
        cleaned_items = []
        for item in value:
            dropped = drop_none(item)
            if dropped is not None:
                cleaned_items.append(dropped)
        return cleaned_items
    return value


def redact_tree(value: Any, *, sensitive_terms: tuple[str, ...]) -> Any:
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            lower_key = key.lower()
            if any(term in lower_key for term in sensitive_terms):
                redacted[key] = "<redacted>"
            else:
                redacted[key] = redact_tree(item, sensitive_terms=sensitive_terms)
        return redacted
    if isinstance(value, list):
        return [redact_tree(item, sensitive_terms=sensitive_terms) for item in value]
    return value
