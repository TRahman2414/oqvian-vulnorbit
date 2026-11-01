from __future__ import annotations

from collections.abc import Iterable
from typing import Any

import httpx

OSV_API = "https://api.osv.dev"


class SourceError(RuntimeError):
    """Raised when an intelligence source cannot return a valid response."""


class OSVClient:
    def __init__(self, timeout: float = 12.0, client: httpx.Client | None = None) -> None:
        self.timeout = timeout
        self.client = client

    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        try:
            if self.client:
                response = self.client.post(f"{OSV_API}{path}", json=payload, timeout=self.timeout)
            else:
                response = httpx.post(f"{OSV_API}{path}", json=payload, timeout=self.timeout)
            response.raise_for_status()
            value = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise SourceError(f"OSV request failed: {exc}") from exc
        if not isinstance(value, dict):
            raise SourceError("OSV returned a response that was not an object")
        return value

    def _get(self, path: str) -> dict[str, Any]:
        try:
            if self.client:
                response = self.client.get(f"{OSV_API}{path}", timeout=self.timeout)
            else:
                response = httpx.get(f"{OSV_API}{path}", timeout=self.timeout)
            response.raise_for_status()
            value = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise SourceError(f"OSV request failed: {exc}") from exc
        if not isinstance(value, dict):
            raise SourceError("OSV returned a response that was not an object")
        return value

    @staticmethod
    def _query(package_name: str, ecosystem: str, version: str) -> dict[str, Any]:
        return {
            "package": {"name": package_name, "ecosystem": ecosystem},
            "version": version,
        }

    def query_version(self, package_name: str, ecosystem: str, version: str) -> list[dict[str, Any]]:
        """Query one exact package version and follow OSV pagination tokens."""
        payload = self._query(package_name, ecosystem, version)
        records: dict[str, dict[str, Any]] = {}
        page_count = 0
        while True:
            response = self._post("/v1/query", payload)
            vulns = response.get("vulns", [])
            if not isinstance(vulns, list):
                raise SourceError("OSV response has an invalid vulns field")
            for record in vulns:
                if isinstance(record, dict) and isinstance(record.get("id"), str):
                    records[record["id"]] = record
            token = response.get("next_page_token")
            if not token:
                break
            page_count += 1
            if page_count >= 20:
                raise SourceError("OSV pagination exceeded the safety limit")
            payload["page_token"] = token
        return list(records.values())

    def query_batch(self, packages: Iterable[dict[str, str]]) -> list[list[dict[str, Any]]]:
        """Batch package/version queries, fetching full records when only IDs are returned."""
        rows = list(packages)
        if not rows:
            return []
        queries = [self._query(row["package_name"], row["ecosystem"], row["version"]) for row in rows]
        response = self._post("/v1/querybatch", {"queries": queries})
        results = response.get("results")
        if not isinstance(results, list) or len(results) != len(rows):
            raise SourceError("OSV batch response did not align with the submitted package list")
        output: list[list[dict[str, Any]]] = []
        for index, result in enumerate(results):
            if not isinstance(result, dict):
                raise SourceError("OSV batch response contains an invalid result")
            if result.get("next_page_token"):
                row = rows[index]
                output.append(self.query_version(row["package_name"], row["ecosystem"], row["version"]))
                continue
            items = result.get("vulns", [])
            if not isinstance(items, list):
                raise SourceError("OSV batch result has an invalid vulns field")
            full_records: list[dict[str, Any]] = []
            for item in items:
                if not isinstance(item, dict) or not isinstance(item.get("id"), str):
                    continue
                if "affected" in item:
                    full_records.append(item)
                else:
                    full_records.append(self._get(f"/v1/vulns/{item['id']}"))
            output.append(full_records)
        return output
