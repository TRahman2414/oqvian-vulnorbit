from __future__ import annotations

import re
from typing import Any

import httpx

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


class CISAKEVError(RuntimeError):
    """Raised when the CISA KEV catalog is unavailable or malformed."""


def validate_catalog(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities"), list):
        raise CISAKEVError("CISA KEV payload must contain a vulnerabilities list")
    version = payload.get("catalogVersion")
    released = payload.get("dateReleased")
    if not isinstance(version, str) or not isinstance(released, str):
        raise CISAKEVError("CISA KEV catalog metadata is missing")
    seen: set[str] = set()
    for entry in payload["vulnerabilities"]:
        if not isinstance(entry, dict):
            raise CISAKEVError("CISA KEV contains an invalid record")
        cve_id = entry.get("cveID")
        if not isinstance(cve_id, str) or not _CVE.fullmatch(cve_id):
            raise CISAKEVError("CISA KEV contains an invalid CVE identifier")
        normalized = cve_id.upper()
        if normalized in seen:
            raise CISAKEVError(f"CISA KEV contains duplicate CVE {normalized}")
        seen.add(normalized)
    return payload


class CISAKEVClient:
    def __init__(self, timeout: float = 15.0, client: httpx.Client | None = None) -> None:
        self.timeout = timeout
        self.client = client

    def fetch(self) -> dict[str, Any]:
        try:
            if self.client:
                response = self.client.get(CISA_KEV_URL, timeout=self.timeout)
            else:
                response = httpx.get(CISA_KEV_URL, timeout=self.timeout)
            response.raise_for_status()
            return validate_catalog(response.json())
        except (httpx.HTTPError, ValueError) as exc:
            raise CISAKEVError(f"CISA KEV request failed: {exc}") from exc
