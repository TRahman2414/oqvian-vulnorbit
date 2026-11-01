from __future__ import annotations

from typing import Any


def prioritize(
    match_state: str,
    kev_status: str,
    internet_exposed: bool,
    criticality: str,
    severity: str | None = None,
    source_fresh: bool = True,
) -> tuple[str, list[str]]:
    """Return a deterministic priority and the conditions that produced it."""
    if not source_fresh:
        return "Review required", ["The vulnerability intelligence snapshot is stale or degraded."]
    if match_state != "confirmed_affected":
        return "Review required", ["The package/version match is not confirmed."]
    if kev_status == "unknown":
        return "Review required", ["KEV status is unavailable or stale; exploitation status is unknown."]
    if kev_status == "listed":
        reasons = ["The confirmed vulnerability is listed in the CISA KEV catalog."]
        if internet_exposed:
            reasons.append("The affected asset is marked internet-exposed in the fictional inventory.")
        if criticality == "critical":
            reasons.append("The affected asset has critical business criticality in the demo inventory.")
        if internet_exposed and criticality == "critical":
            return "P1 — Urgent review", reasons
        return "P2 — High-priority review", reasons
    reasons = ["OSV confirms the recorded package version is affected.", "No matching CISA KEV entry was present in the available catalog."]
    if severity:
        reasons.append(f"Source-reported severity: {severity}.")
    if severity and severity.upper() in {"CRITICAL", "HIGH"}:
        return "P2 — High-priority review", reasons
    return "P3 — Standard review", reasons
