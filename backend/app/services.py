from __future__ import annotations

import json
import sqlite3
import uuid
from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import Any

from .adapters.cisa_kev import CISA_KEV_URL, CISAKEVClient, CISAKEVError, validate_catalog
from .adapters.osv import OSV_API, OSVClient, SourceError
from .database import _save_cache, connect
from .matching import canonical_advisory_key, classify_osv_record, normalize_cve
from .prioritization import prioritize

STALE_AFTER = timedelta(days=7)


def now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _is_stale(timestamp: str | None) -> bool:
    if not timestamp:
        return True
    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        return True
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return datetime.now(UTC) - parsed.astimezone(UTC) > STALE_AFTER


def row_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    return dict(row) if row is not None else None


def _upsert_advisory(connection: sqlite3.Connection, record: dict[str, Any], source_url: str) -> None:
    advisory_id = record.get("id")
    if not isinstance(advisory_id, str) or not advisory_id.strip():
        raise SourceError("OSV record has no advisory ID")
    connection.execute(
        """INSERT INTO advisories
           (advisory_id,aliases_json,summary,details,published,modified,source_url,raw_json)
           VALUES(?,?,?,?,?,?,?,?)
           ON CONFLICT(advisory_id) DO UPDATE SET aliases_json=excluded.aliases_json,
            summary=excluded.summary, details=excluded.details, published=excluded.published,
            modified=excluded.modified, source_url=excluded.source_url, raw_json=excluded.raw_json""",
        (advisory_id, json.dumps(record.get("aliases", [])), record.get("summary", ""),
         record.get("details", ""), record.get("published"), record.get("modified"),
         source_url, json.dumps(record)),
    )


def _severity_level(record: dict[str, Any]) -> str | None:
    candidates = [record.get("database_specific"), record.get("ecosystem_specific")]
    candidates.extend(
        affected.get("ecosystem_specific")
        for affected in record.get("affected", [])
        if isinstance(affected, dict)
    )
    for candidate in candidates:
        if isinstance(candidate, dict) and isinstance(candidate.get("severity"), str):
            value = candidate["severity"].strip().upper()
            if value in {"CRITICAL", "HIGH", "MODERATE", "MEDIUM", "LOW"}:
                return value
    return None


def _set_feed_state(
    connection: sqlite3.Connection,
    source: str,
    status: str,
    mode: str,
    checked_at: str,
    last_success_at: str | None,
    source_version: str | None,
    last_error: str | None,
) -> None:
    connection.execute(
        """INSERT INTO feed_state
           (source,status,mode,checked_at,last_success_at,source_version,last_error)
           VALUES(?,?,?,?,?,?,?)
           ON CONFLICT(source) DO UPDATE SET status=excluded.status, mode=excluded.mode,
            checked_at=excluded.checked_at,
            last_success_at=COALESCE(excluded.last_success_at,feed_state.last_success_at),
            source_version=COALESCE(excluded.source_version,feed_state.source_version),
            last_error=excluded.last_error""",
        (source, status, mode, checked_at, last_success_at, source_version, last_error),
    )


def refresh_intelligence(db_path: str | None = None) -> dict[str, Any]:
    """Refresh each source independently; failed refreshes preserve the last valid snapshot."""
    result: dict[str, Any] = {"sources": {}}
    with connect(db_path) as connection:
        package_rows = connection.execute(
            """SELECT DISTINCT package_name,ecosystem,version FROM components
               WHERE version IS NOT NULL ORDER BY ecosystem,package_name,version"""
        ).fetchall()
    queries = [
        {"package_name": row["package_name"], "ecosystem": row["ecosystem"], "version": row["version"]}
        for row in package_rows
    ]

    checked = now_iso()
    try:
        osv_client = OSVClient()
        advisory_sets = osv_client.query_batch(queries)
        retrieved = now_iso()
        with connect(db_path) as connection:
            # A successful batch is a complete snapshot for the inventory queried here.
            # Replace the advisory table in the same transaction as the cache writes so
            # advisories that disappeared upstream cannot remain matchable indefinitely.
            records_by_id: dict[str, dict[str, Any]] = {}
            for query, records in zip(queries, advisory_sets, strict=True):
                key = f"osv|{query['ecosystem']}|{query['package_name']}|{query['version']}"
                payload = {"vulns": records}
                _save_cache(connection, key, "OSV", payload, f"{OSV_API}/v1/query", retrieved,
                            "live", query["package_name"], query["ecosystem"], query["version"])
                for record in records:
                    records_by_id[record["id"]] = record
            connection.execute("DELETE FROM advisories")
            for record in records_by_id.values():
                _upsert_advisory(connection, record, f"{OSV_API}/v1/vulns/{record['id']}")
            _set_feed_state(connection, "OSV", "available", "live", checked, retrieved,
                            "v1/querybatch", None)
        result["sources"]["OSV"] = {"status": "available", "mode": "live", "retrieved_at": retrieved,
                                      "queries": len(queries)}
    except (SourceError, KeyError, TypeError, ValueError) as exc:
        with connect(db_path) as connection:
            _set_feed_state(connection, "OSV", "degraded", "cached", checked, None, None, str(exc))
        result["sources"]["OSV"] = {"status": "degraded", "error": str(exc)}

    checked = now_iso()
    try:
        kev_catalog = CISAKEVClient().fetch()
        retrieved = now_iso()
        catalog_version = kev_catalog.get("catalogVersion")
        with connect(db_path) as connection:
            _save_cache(connection, "cisa-kev|catalog", "CISA KEV", kev_catalog,
                        CISA_KEV_URL, retrieved, "live")
            _set_feed_state(connection, "CISA KEV", "available", "live", checked, retrieved,
                            str(catalog_version) if catalog_version else None, None)
        result["sources"]["CISA KEV"] = {"status": "available", "mode": "live",
                                          "retrieved_at": retrieved,
                                          "catalog_version": catalog_version,
                                          "record_count": len(kev_catalog["vulnerabilities"])}
    except CISAKEVError as exc:
        with connect(db_path) as connection:
            _set_feed_state(connection, "CISA KEV", "degraded", "cached", checked, None, None, str(exc))
        result["sources"]["CISA KEV"] = {"status": "degraded", "error": str(exc)}
    return result


def intelligence_status(db_path: str | None = None) -> list[dict[str, Any]]:
    with connect(db_path) as connection:
        rows = connection.execute("SELECT * FROM feed_state ORDER BY source").fetchall()
        output = []
        for row in rows:
            item = dict(row)
            if row["source"] == "CISA KEV":
                cache = connection.execute(
                    "SELECT mode,retrieved_at FROM source_cache WHERE cache_key='cisa-kev|catalog'"
                ).fetchone()
            else:
                cache = connection.execute(
                    "SELECT MIN(mode) AS mode,MIN(retrieved_at) AS retrieved_at "
                    "FROM source_cache WHERE source='OSV'"
                ).fetchone()
            if row["status"] == "available" and cache and _is_stale(cache["retrieved_at"]):
                item["status"] = "stale"
            elif row["status"] == "available" and cache and cache["mode"] == "demo_fixture":
                item["status"] = "partial"
            output.append(item)
    return output


def _kev_index(connection: sqlite3.Connection) -> tuple[dict[str, dict[str, Any]], str, str | None]:
    cache = connection.execute(
        "SELECT * FROM source_cache WHERE cache_key='cisa-kev|catalog'"
    ).fetchone()
    state = connection.execute("SELECT * FROM feed_state WHERE source='CISA KEV'").fetchone()
    if not cache:
        return {}, "unknown", None
    payload = json.loads(cache["payload_json"])
    entries = payload.get("vulnerabilities", [])
    version = payload.get("catalogVersion")
    stale = (state is not None and state["status"] == "degraded") or _is_stale(cache["retrieved_at"])
    partial_fixture = cache["mode"] == "demo_fixture"
    index = {
        entry["cveID"].upper(): entry for entry in entries
        if isinstance(entry, dict) and isinstance(entry.get("cveID"), str)
    }
    if stale:
        return index, "stale", version
    if partial_fixture:
        return index, "partial", version
    return index, "available", version


def run_detection(db_path: str | None = None, mode: str = "demo") -> dict[str, Any]:
    if mode not in {"demo", "live"}:
        raise ValueError("mode must be 'demo' or 'live'")
    if mode == "live":
        refresh_intelligence(db_path)

    run_id = f"run-{uuid.uuid4().hex[:12]}"
    started = now_iso()
    with connect(db_path) as connection:
        connection.execute(
            "INSERT INTO scan_runs(id,scenario,mode,status,started_at) VALUES(?,?,?,?,?)",
            (run_id, "log4shell", mode, "running", started),
        )
        kev_index, kev_feed_state, kev_version = _kev_index(connection)
        osv_state = connection.execute("SELECT status FROM feed_state WHERE source='OSV'").fetchone()
        osv_degraded = osv_state is not None and osv_state["status"] == "degraded"
        advisory_rows = connection.execute("SELECT * FROM advisories ORDER BY advisory_id").fetchall()
        component_rows = connection.execute(
            """SELECT c.*,a.hostname,a.criticality,a.internet_exposed,o.name AS organization
               FROM components c JOIN assets a ON a.id=c.asset_id
               JOIN organizations o ON o.id=a.organization_id ORDER BY c.id"""
        ).fetchall()
        cache_rows = connection.execute("SELECT * FROM source_cache WHERE source='OSV'").fetchall()
        cache_keys = {
            (row["package_name"], row["ecosystem"], row["version"]): row for row in cache_rows
        }
        records = []
        for row in advisory_rows:
            raw = json.loads(row["raw_json"])
            records.append((dict(row), raw))

        finding_count = 0
        case_count = 0
        unverified_components = 0
        not_affected_count = 0
        result_counts: Counter[str] = Counter()
        affected_component_ids: set[str] = set()

        for component in component_rows:
            exact_query = cache_keys.get((component["package_name"], component["ecosystem"], component["version"]))
            package_has_snapshot = any(
                row["package_name"] == component["package_name"] and row["ecosystem"] == component["ecosystem"]
                for row in cache_rows
            )
            if not exact_query and not package_has_snapshot:
                unverified_components += 1
            applicable_record_count = 0
            for advisory_row, record in records:
                classification = classify_osv_record(
                    record, component["package_name"], component["ecosystem"], component["version"]
                )
                if classification == "unverified":
                    continue
                applicable_record_count += 1
                key = canonical_advisory_key(record)
                cve_id = normalize_cve(key)
                result_counts[classification] += 1
                connection.execute(
                    "INSERT OR REPLACE INTO scan_results(run_id,component_id,advisory_key,match_state) VALUES(?,?,?,?)",
                    (run_id, component["id"], key, classification),
                )
                if classification == "not_affected":
                    not_affected_count += 1
                    continue

                cisa_entry = kev_index.get(cve_id) if cve_id else None
                if cisa_entry:
                    kev_status = "listed"
                elif kev_feed_state == "available":
                    kev_status = "not_listed"
                else:
                    kev_status = "unknown"
                severity = _severity_level(record)
                osv_stale = osv_degraded or (exact_query is not None and _is_stale(exact_query["retrieved_at"]))
                priority, reasons = prioritize(
                    classification, kev_status, bool(component["internet_exposed"]),
                    component["criticality"], severity, source_fresh=not osv_stale,
                )
                identifier = f"finding-{uuid.uuid5(uuid.NAMESPACE_URL, f'{component['asset_id']}|{component['id']}|{key}').hex[:16]}"
                updated_at = now_iso()
                evidence = {
                    "osv": {
                        "id": record.get("id"),
                        "aliases": record.get("aliases", []),
                        "source_url": advisory_row["source_url"],
                        "retrieved_at": exact_query["retrieved_at"] if exact_query else advisory_row["modified"],
                        "summary": record.get("summary", ""),
                        "package": component["package_name"],
                        "ecosystem": component["ecosystem"],
                        "version": component["version"],
                        "snapshot_status": (
                            "missing" if exact_query is None else
                            "stale" if osv_stale else
                            "partial" if exact_query["mode"] == "demo_fixture" else "available"
                        ),
                    },
                    "cisa_kev": {
                        "status": kev_status,
                        "source_url": CISA_KEV_URL,
                        "catalog_version": kev_version,
                        "entry": cisa_entry,
                    },
                    "asset_context": {
                        "host": component["hostname"],
                        "organization": component["organization"],
                        "criticality": component["criticality"],
                        "internet_exposed": bool(component["internet_exposed"]),
                    },
                    "mode": mode,
                }
                connection.execute(
                    """INSERT INTO findings
                       (id,asset_id,component_id,advisory_key,advisory_id,cve_id,match_state,kev_status,
                        priority,priority_reasons_json,evidence_json,status,updated_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,'open',?)
                       ON CONFLICT(asset_id,component_id,advisory_key) DO UPDATE SET
                        advisory_id=excluded.advisory_id,cve_id=excluded.cve_id,
                        match_state=excluded.match_state,kev_status=excluded.kev_status,
                        priority=excluded.priority,priority_reasons_json=excluded.priority_reasons_json,
                        evidence_json=excluded.evidence_json,status='open',updated_at=excluded.updated_at""",
                    (identifier, component["asset_id"], component["id"], key, advisory_row["advisory_id"],
                     cve_id, classification, kev_status, priority, json.dumps(reasons),
                     json.dumps(evidence), updated_at),
                )
                finding = connection.execute(
                    "SELECT id FROM findings WHERE asset_id=? AND component_id=? AND advisory_key=?",
                    (component["asset_id"], component["id"], key),
                ).fetchone()
                finding_id = finding["id"]
                case_id = f"case-{uuid.uuid5(uuid.NAMESPACE_URL, finding_id).hex[:16]}"
                connection.execute(
                    """INSERT OR IGNORE INTO cases(id,finding_id,status,assignee,notes_json,created_at,updated_at)
                       VALUES(?,?,'open',NULL,'[]',?,?)""",
                    (case_id, finding_id, updated_at, updated_at),
                )
                connection.execute(
                    "INSERT INTO audit_events(event_type,subject_id,details_json,created_at) VALUES(?,?,?,?)",
                    ("finding.detected", finding_id,
                     json.dumps({"run_id": run_id, "priority": priority, "source_mode": mode}), updated_at),
                )
                affected_component_ids.add(component["id"])
                finding_count += 1
                case_count += 1
            if not applicable_record_count and package_has_snapshot and not exact_query:
                # Other versions of a known package remain uncovered by that package/version snapshot.
                unverified_components += 1

        summary = {
            "findings": finding_count,
            "cases": connection.execute("SELECT COUNT(*) FROM cases").fetchone()[0],
            "components_checked": len(component_rows),
            "unverified_components": unverified_components,
            "not_affected_by_selected_advisory": not_affected_count,
            "match_results": dict(result_counts),
            "coverage": "partial" if unverified_components else "complete",
            "source_mode": mode,
        }
        completed = now_iso()
        connection.execute(
            "UPDATE scan_runs SET status='complete',completed_at=?,summary_json=? WHERE id=?",
            (completed, json.dumps(summary), run_id),
        )
        connection.execute(
            "INSERT INTO audit_events(event_type,subject_id,details_json,created_at) VALUES(?,?,?,?)",
            ("detection.completed", run_id, json.dumps(summary), completed),
        )
    return {"run_id": run_id, "status": "complete", "completed_at": completed, **summary}


def overview(db_path: str | None = None) -> dict[str, Any]:
    with connect(db_path) as connection:
        assets = connection.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
        orgs = connection.execute("SELECT COUNT(*) FROM organizations").fetchone()[0]
        findings = connection.execute("SELECT COUNT(*) FROM findings WHERE status='open'").fetchone()[0]
        cases = connection.execute("SELECT COUNT(*) FROM cases WHERE status IN ('open','in_progress')").fetchone()[0]
        priorities = {
            row["priority"]: row["count"] for row in connection.execute(
                "SELECT priority,COUNT(*) AS count FROM findings WHERE status='open' GROUP BY priority"
            )
        }
        last_run = connection.execute(
            "SELECT id,mode,status,completed_at,summary_json FROM scan_runs ORDER BY started_at DESC LIMIT 1"
        ).fetchone()
    return {
        "organizations": orgs,
        "assets": assets,
        "open_findings": findings,
        "active_cases": cases,
        "priorities": priorities,
        "last_run": ({**dict(last_run), "summary": json.loads(last_run["summary_json"])} if last_run else None),
        "inventory_mode": "fictional_demo_data",
    }


def list_assets(db_path: str | None = None, organization_id: str | None = None) -> list[dict[str, Any]]:
    with connect(db_path) as connection:
        sql = """SELECT a.*,o.name AS organization FROM assets a
                 JOIN organizations o ON o.id=a.organization_id"""
        params: tuple[Any, ...] = ()
        if organization_id:
            sql += " WHERE a.organization_id=?"
            params = (organization_id,)
        sql += " ORDER BY o.name,a.hostname"
        rows = connection.execute(sql, params).fetchall()
        output = []
        for row in rows:
            item = dict(row)
            item["internet_exposed"] = bool(item["internet_exposed"])
            item["components"] = [dict(component) for component in connection.execute(
                "SELECT id,package_name,ecosystem,version,purl FROM components WHERE asset_id=? ORDER BY package_name",
                (item["id"],),
            )]
            output.append(item)
    return output


def list_findings(db_path: str | None = None) -> list[dict[str, Any]]:
    with connect(db_path) as connection:
        rows = connection.execute(
            """SELECT f.*,a.hostname,o.name AS organization,c.package_name,c.ecosystem,c.version
               FROM findings f JOIN assets a ON a.id=f.asset_id
               JOIN organizations o ON o.id=a.organization_id
               JOIN components c ON c.id=f.component_id
               ORDER BY CASE WHEN f.priority LIKE 'P1%' THEN 1 WHEN f.priority LIKE 'P2%' THEN 2 ELSE 3 END,
                        f.updated_at DESC"""
        ).fetchall()
    return [_finding_payload(row) for row in rows]


def _finding_payload(row: sqlite3.Row) -> dict[str, Any]:
    result = dict(row)
    result["priority_reasons"] = json.loads(result.pop("priority_reasons_json"))
    result["evidence"] = json.loads(result.pop("evidence_json"))
    return result


def get_finding(finding_id: str, db_path: str | None = None) -> dict[str, Any] | None:
    with connect(db_path) as connection:
        row = connection.execute(
            """SELECT f.*,a.hostname,o.name AS organization,c.package_name,c.ecosystem,c.version
               FROM findings f JOIN assets a ON a.id=f.asset_id
               JOIN organizations o ON o.id=a.organization_id
               JOIN components c ON c.id=f.component_id WHERE f.id=?""",
            (finding_id,),
        ).fetchone()
        if not row:
            return None
        payload = _finding_payload(row)
        case = row_dict(connection.execute("SELECT * FROM cases WHERE finding_id=?", (finding_id,)).fetchone())
        if case is not None:
            case["notes"] = json.loads(case.pop("notes_json"))
        payload["case"] = case
        return payload


def list_cases(db_path: str | None = None) -> list[dict[str, Any]]:
    with connect(db_path) as connection:
        rows = connection.execute(
            """SELECT ca.*,f.cve_id,f.priority,f.status AS finding_status,
                      a.hostname,o.name AS organization,c.package_name,c.version
               FROM cases ca JOIN findings f ON f.id=ca.finding_id
               JOIN assets a ON a.id=f.asset_id JOIN organizations o ON o.id=a.organization_id
               JOIN components c ON c.id=f.component_id ORDER BY ca.updated_at DESC"""
        ).fetchall()
    output = []
    for row in rows:
        item = dict(row)
        item["notes"] = json.loads(item.pop("notes_json"))
        output.append(item)
    return output


def update_case(
    case_id: str, status: str | None, assignee: str | None, db_path: str | None = None
) -> dict[str, Any] | None:
    allowed = {"open", "in_progress", "resolved", "accepted_risk"}
    if status is not None and status not in allowed:
        raise ValueError(f"status must be one of {sorted(allowed)}")
    with connect(db_path) as connection:
        row = connection.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
        if not row:
            return None
        next_status = status or row["status"]
        next_assignee = assignee if assignee is not None else row["assignee"]
        updated = now_iso()
        connection.execute("UPDATE cases SET status=?,assignee=?,updated_at=? WHERE id=?",
                           (next_status, next_assignee, updated, case_id))
        connection.execute("INSERT INTO audit_events(event_type,subject_id,details_json,created_at) VALUES(?,?,?,?)",
                           ("case.updated", case_id, json.dumps({"status": next_status, "assignee": next_assignee}), updated))
        result = dict(connection.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone())
        result["notes"] = json.loads(result.pop("notes_json"))
    return result


def add_case_note(case_id: str, note: str, author: str = "Analyst", db_path: str | None = None) -> dict[str, Any] | None:
    cleaned = note.strip()
    if not cleaned or len(cleaned) > 2000:
        raise ValueError("note must contain 1 to 2000 characters")
    with connect(db_path) as connection:
        row = connection.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
        if not row:
            return None
        notes = json.loads(row["notes_json"])
        entry = {"author": author[:80], "text": cleaned, "created_at": now_iso()}
        notes.append(entry)
        connection.execute("UPDATE cases SET notes_json=?,updated_at=? WHERE id=?",
                           (json.dumps(notes), entry["created_at"], case_id))
        connection.execute("INSERT INTO audit_events(event_type,subject_id,details_json,created_at) VALUES(?,?,?,?)",
                           ("case.note_added", case_id, json.dumps({"author": entry["author"]}), entry["created_at"]))
        result = dict(connection.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone())
        result["notes"] = json.loads(result.pop("notes_json"))
    return result

