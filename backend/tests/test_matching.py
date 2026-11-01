import json
from pathlib import Path

from app.matching import (
    canonical_advisory_key,
    classify_osv_record,
    normalize_cve,
)
from app.prioritization import prioritize


def _saved_log4shell_record():
    fixture = Path(__file__).resolve().parents[1] / "fixtures" / "osv_log4shell.json"
    return json.loads(fixture.read_text())["record"]


def test_log4j_core_maven_2_14_1_confirmed_affected_by_saved_osv_advisory():
    osv_record = _saved_log4shell_record()
    state = classify_osv_record(
        osv_record,
        package_name="org.apache.logging.log4j:log4j-core",
        ecosystem="Maven",
        version="2.14.1",
    )
    assert state == "confirmed_affected"


def test_log4j_core_maven_2_17_1_not_affected_by_cve_2021_44228():
    osv_record = _saved_log4shell_record()
    state = classify_osv_record(
        osv_record,
        package_name="org.apache.logging.log4j:log4j-core",
        ecosystem="Maven",
        version="2.17.1",
    )
    assert state == "not_affected"


def test_missing_version_is_unverified():
    osv_record = {
        "id": "GHSA-XXXX",
        "aliases": ["CVE-2021-12345"],
        "affected": [
            {
                "package": {"name": "example/pkg", "ecosystem": "npm"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.0.0"}]}
                ],
            }
        ],
    }
    assert classify_osv_record(osv_record, "example/pkg", "npm", None) == "unverified"
    assert classify_osv_record(osv_record, "example/pkg", "npm", "") == "unverified"


def test_package_identity_mismatch_is_unverified():
    osv_record = {
        "id": "GHSA-XXXX",
        "aliases": ["CVE-2021-12345"],
        "affected": [
            {
                "package": {"name": "example/pkg", "ecosystem": "npm"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.0.0"}]}
                ],
            }
        ],
    }
    # Different package name
    assert classify_osv_record(osv_record, "other/pkg", "npm", "0.9.0") == "unverified"
    # Different ecosystem
    assert classify_osv_record(osv_record, "example/pkg", "PyPI", "0.9.0") == "unverified"


def test_malformed_cve_aliases_do_not_become_canonical_cves():
    # Malformed/mixed cases - only valid CVE should be canonical
    record_bad = {"id": "GHSA-ABC", "aliases": ["CVE-2021-44228X", "not-a-cve", "CVE-2021-442"]}
    assert canonical_advisory_key(record_bad) == "GHSA-ABC"

    # Multiple valid and invalid - should pick valid canonical CVE
    record_mixed = {"id": "GHSA-XYZ", "aliases": ["cve-2021-44228", "BAD-CVE-123", "CVE-2021-45046"]}
    # normalize_cve uppercases and validates format
    assert canonical_advisory_key(record_mixed) == "CVE-2021-44228"  # sorted lexicographically

    # No valid CVEs at all
    record_none = {"id": "my-advisory", "aliases": ["invalid", "CVE-123"]}
    assert canonical_advisory_key(record_none) == "MY-ADVISORY"


def test_priority_p1_only_for_confirmed_kev_internet_exposed_critical():
    # P1: confirmed + KEV listed + internet-exposed + critical
    priority, reasons = prioritize(
        match_state="confirmed_affected",
        kev_status="listed",
        internet_exposed=True,
        criticality="critical",
    )
    assert priority == "P1 — Urgent review"
    assert isinstance(reasons, list)
    assert len(reasons) > 0

    # Not P1 cases
    # confirmed + KEV listed but not internet-exposed and not critical
    priority, reasons = prioritize(
        match_state="confirmed_affected",
        kev_status="listed",
        internet_exposed=False,
        criticality="high",
    )
    assert priority != "P1 — Urgent review"

    # confirmed + KEV listed but internet-exposed true, critical false
    priority, reasons = prioritize(
        match_state="confirmed_affected",
        kev_status="listed",
        internet_exposed=True,
        criticality="high",
    )
    assert priority != "P1 — Urgent review"

    # confirmed + KEV listed but internet-exposed false, critical true
    priority, reasons = prioritize(
        match_state="confirmed_affected",
        kev_status="listed",
        internet_exposed=False,
        criticality="critical",
    )
    assert priority != "P1 — Urgent review"


def test_unknown_kev_never_becomes_p3():
    priority, reasons = prioritize(
        match_state="confirmed_affected",
        kev_status="unknown",
        internet_exposed=True,
        criticality="critical",
    )
    assert priority != "P3 — Standard review"
    assert priority == "Review required"
    assert any("KEV" in r for r in reasons)
