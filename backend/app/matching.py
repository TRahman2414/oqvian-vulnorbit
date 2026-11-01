from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any, Literal

from packaging.version import InvalidVersion, Version

MatchState = Literal["confirmed_affected", "not_affected", "unverified"]
_NUMERIC_VERSION = re.compile(r"^\d+(?:\.\d+)*$")


def normalize_cve(value: str) -> str | None:
    candidate = value.strip().upper()
    return candidate if re.fullmatch(r"CVE-\d{4}-\d{4,}", candidate) else None


def canonical_advisory_key(record: Mapping[str, Any]) -> str:
    aliases = record.get("aliases") or []
    cves = sorted({value for item in aliases if isinstance(item, str) if (value := normalize_cve(item))})
    return cves[0] if cves else str(record.get("id", "unknown-advisory")).upper()


def _version_tuple(value: str) -> tuple[int, ...] | None:
    if not _NUMERIC_VERSION.fullmatch(value):
        return None
    try:
        return tuple(int(part) for part in value.split("."))
    except ValueError:
        return None


def _compare(left: str, right: str) -> int | None:
    try:
        left_version, right_version = Version(left), Version(right)
    except InvalidVersion:
        left_parts, right_parts = _version_tuple(left), _version_tuple(right)
        if left_parts is None or right_parts is None:
            return None
        width = max(len(left_parts), len(right_parts))
        left_parts += (0,) * (width - len(left_parts))
        right_parts += (0,) * (width - len(right_parts))
        return (left_parts > right_parts) - (left_parts < right_parts)
    return (left_version > right_version) - (left_version < right_version)


def _package_matches(affected: Mapping[str, Any], package_name: str, ecosystem: str) -> bool:
    package = affected.get("package") or {}
    return (
        isinstance(package, Mapping)
        and package.get("name") == package_name
        and str(package.get("ecosystem", "")).casefold() == ecosystem.casefold()
    )


def _range_contains(version: str, events: list[dict[str, Any]]) -> bool | None:
    start: str | None = None
    had_supported_event = False
    for event in events:
        if not isinstance(event, dict):
            continue
        if "introduced" in event:
            start = str(event["introduced"])
            had_supported_event = True
        elif "fixed" in event or "last_affected" in event:
            end_key = "fixed" if "fixed" in event else "last_affected"
            end = str(event[end_key])
            had_supported_event = True
            start_value = start or "0"
            lower = _compare(version, start_value)
            upper = _compare(version, end)
            if lower is None or upper is None:
                return None
            if lower >= 0 and (upper < 0 if end_key == "fixed" else upper <= 0):
                return True
            start = None
    if start is not None:
        lower = _compare(version, start)
        if lower is None:
            return None
        return lower >= 0
    return False if had_supported_event else None


def classify_osv_record(
    record: Mapping[str, Any], package_name: str, ecosystem: str, version: str | None
) -> MatchState:
    """Classify only supported exact package/version evidence; unknown data stays unverified."""
    if not version:
        return "unverified"
    affected_entries = record.get("affected")
    if not isinstance(affected_entries, list):
        return "unverified"
    matched_package = [
        entry for entry in affected_entries
        if isinstance(entry, Mapping) and _package_matches(entry, package_name, ecosystem)
    ]
    if not matched_package:
        return "unverified"

    unresolved = False
    supported = False
    for entry in matched_package:
        explicit_versions = entry.get("versions") or []
        if isinstance(explicit_versions, list) and version in explicit_versions:
            return "confirmed_affected"
        ranges = entry.get("ranges") or []
        if not isinstance(ranges, list):
            unresolved = True
            continue
        for version_range in ranges:
            if not isinstance(version_range, Mapping) or version_range.get("type") != "ECOSYSTEM":
                unresolved = True
                continue
            events = version_range.get("events")
            if not isinstance(events, list):
                unresolved = True
                continue
            result = _range_contains(version, events)
            if result is True:
                return "confirmed_affected"
            if result is None:
                unresolved = True
            else:
                supported = True
    if unresolved or not supported:
        return "unverified"
    return "not_affected"
