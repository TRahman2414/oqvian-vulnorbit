import json
from pathlib import Path

import pytest

from app.adapters.cisa_kev import CISAKEVError, validate_catalog


def test_saved_cisa_fixture_contains_the_log4shell_kev_record():
    fixture_path = Path(__file__).resolve().parents[1] / "fixtures" / "cisa_kev_log4shell.json"
    fixture = json.loads(fixture_path.read_text())
    catalog = validate_catalog(fixture)
    assert catalog["catalogVersion"]
    assert catalog["vulnerabilities"][0]["cveID"] == "CVE-2021-44228"


def test_cisa_catalog_rejects_duplicate_cve_ids():
    duplicate = {
        "catalogVersion": "test",
        "dateReleased": "2026-11-01T00:00:00Z",
        "vulnerabilities": [
            {"cveID": "CVE-2021-44228"},
            {"cveID": "cve-2021-44228"},
        ],
    }
    with pytest.raises(CISAKEVError, match="duplicate CVE"):
        validate_catalog(duplicate)


def test_cisa_catalog_rejects_records_without_valid_cve_ids():
    invalid = {
        "catalogVersion": "test",
        "dateReleased": "2026-11-01T00:00:00Z",
        "vulnerabilities": [{"cveID": "not-a-cve"}],
    }
    with pytest.raises(CISAKEVError, match="invalid CVE"):
        validate_catalog(invalid)
