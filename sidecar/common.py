from __future__ import annotations

import datetime as dt
import ipaddress
import json
import sys
from typing import Optional


def emit(event_type: str, **payload: object) -> None:
    line = {"type": event_type, **payload}
    print(json.dumps(line, ensure_ascii=True), flush=True)


def normalize_ip(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    candidate = value.strip().strip("[]")
    if not candidate:
        return None
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


def parse_int(value: object, default: Optional[int] = None) -> Optional[int]:
    if value is None:
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return default
        try:
            return int(text)
        except ValueError:
            return default
    return default


def is_private_ip(value: Optional[str]) -> bool:
    if not value:
        return False
    try:
        ip_obj = ipaddress.ip_address(value)
    except ValueError:
        return False
    return bool(
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_reserved
        or ip_obj.is_multicast
    )


def parse_procmon_timestamp(raw_value: str, base_date: dt.date) -> Optional[int]:
    text = (raw_value or "").strip()
    if not text:
        return None

    direct_formats = [
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%m/%d/%Y %I:%M:%S.%f %p",
        "%m/%d/%Y %I:%M:%S %p",
        "%d/%m/%Y %H:%M:%S.%f",
        "%d/%m/%Y %H:%M:%S",
    ]
    for fmt in direct_formats:
        try:
            parsed = dt.datetime.strptime(text, fmt)
            return int(parsed.replace(tzinfo=dt.timezone.utc).timestamp() * 1_000_000)
        except ValueError:
            continue

    time_only_formats = [
        "%H:%M:%S.%f",
        "%H:%M:%S",
        "%I:%M:%S.%f %p",
        "%I:%M:%S %p",
    ]
    for fmt in time_only_formats:
        try:
            parsed_time = dt.datetime.strptime(text, fmt).time()
            combined = dt.datetime.combine(base_date, parsed_time)
            return int(combined.replace(tzinfo=dt.timezone.utc).timestamp() * 1_000_000)
        except ValueError:
            continue

    try:
        candidate = text.replace("Z", "+00:00")
        parsed_iso = dt.datetime.fromisoformat(candidate)
        if parsed_iso.tzinfo is None:
            parsed_iso = parsed_iso.replace(tzinfo=dt.timezone.utc)
        return int(parsed_iso.timestamp() * 1_000_000)
    except ValueError:
        return None


def stderr(message: str) -> None:
    sys.stderr.write(message + "\n")
    sys.stderr.flush()
