from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .config import FIXTURE_ROOT, database_path

SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS organizations (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, industry TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS assets (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id),
  hostname TEXT NOT NULL,
  asset_type TEXT NOT NULL,
  environment TEXT NOT NULL,
  criticality TEXT NOT NULL CHECK (criticality IN ('critical','high','medium','low')),
  internet_exposed INTEGER NOT NULL CHECK (internet_exposed IN (0,1))
);
CREATE TABLE IF NOT EXISTS components (
  id TEXT PRIMARY KEY,
  asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  package_name TEXT NOT NULL,
  ecosystem TEXT NOT NULL,
  version TEXT,
  purl TEXT
);
CREATE INDEX IF NOT EXISTS ix_components_package ON components(package_name, ecosystem, version);
CREATE TABLE IF NOT EXISTS source_cache (
  cache_key TEXT PRIMARY KEY,
  source TEXT NOT NULL,
  package_name TEXT,
  ecosystem TEXT,
  version TEXT,
  payload_json TEXT NOT NULL,
  source_url TEXT NOT NULL,
  retrieved_at TEXT NOT NULL,
  mode TEXT NOT NULL,
  status TEXT NOT NULL,
  last_error TEXT
);
CREATE TABLE IF NOT EXISTS feed_state (
  source TEXT PRIMARY KEY,
  status TEXT NOT NULL,
  mode TEXT NOT NULL,
  checked_at TEXT NOT NULL,
  last_success_at TEXT,
  source_version TEXT,
  last_error TEXT
);
CREATE TABLE IF NOT EXISTS advisories (
  advisory_id TEXT PRIMARY KEY,
  aliases_json TEXT NOT NULL,
  summary TEXT NOT NULL,
  details TEXT NOT NULL,
  published TEXT,
  modified TEXT,
  source_url TEXT NOT NULL,
  raw_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY,
  asset_id TEXT NOT NULL REFERENCES assets(id),
  component_id TEXT NOT NULL REFERENCES components(id),
  advisory_key TEXT NOT NULL,
  advisory_id TEXT NOT NULL REFERENCES advisories(advisory_id),
  cve_id TEXT,
  match_state TEXT NOT NULL,
  kev_status TEXT NOT NULL,
  priority TEXT NOT NULL,
  priority_reasons_json TEXT NOT NULL,
  evidence_json TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open',
  updated_at TEXT NOT NULL,
  UNIQUE(asset_id, component_id, advisory_key)
);
CREATE TABLE IF NOT EXISTS cases (
  id TEXT PRIMARY KEY,
  finding_id TEXT NOT NULL UNIQUE REFERENCES findings(id),
  status TEXT NOT NULL DEFAULT 'open',
  assignee TEXT,
  notes_json TEXT NOT NULL DEFAULT '[]',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_type TEXT NOT NULL,
  subject_id TEXT NOT NULL,
  details_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scan_runs (
  id TEXT PRIMARY KEY,
  scenario TEXT NOT NULL,
  mode TEXT NOT NULL,
  status TEXT NOT NULL,
  started_at TEXT NOT NULL,
  completed_at TEXT,
  summary_json TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS scan_results (
  run_id TEXT NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
  component_id TEXT NOT NULL REFERENCES components(id),
  advisory_key TEXT NOT NULL,
  match_state TEXT NOT NULL,
  PRIMARY KEY(run_id, component_id, advisory_key)
);
"""

ORGANIZATIONS = [
    ("northstar", "Northstar Finance", "Financial services"),
    ("rivermill", "Rivermill Health", "Healthcare"),
    ("cedar-ridge", "Cedar Ridge Manufacturing", "Manufacturing"),
]

# All hosts and inventory rows below are synthetic demonstration records.
ASSET_ROWS = [
    ("ns-app-01", "northstar", "ns-app-01.demo.local", "application server", "production", "critical", 1),
    ("ns-app-02", "northstar", "ns-app-02.demo.local", "application server", "production", "critical", 0),
    ("ns-api-01", "northstar", "ns-api-01.demo.local", "API server", "production", "high", 1),
    ("ns-db-01", "northstar", "ns-db-01.demo.local", "database", "production", "critical", 0),
    ("ns-web-01", "northstar", "ns-web-01.demo.local", "web server", "production", "high", 1),
    ("ns-batch-01", "northstar", "ns-batch-01.demo.local", "batch worker", "production", "medium", 0),
    ("ns-stage-01", "northstar", "ns-stage-01.demo.local", "application server", "staging", "medium", 0),
    ("ns-admin-01", "northstar", "ns-admin-01.demo.local", "admin workstation", "production", "high", 0),
    ("rh-app-01", "rivermill", "rh-app-01.demo.local", "application server", "production", "critical", 1),
    ("rh-app-02", "rivermill", "rh-app-02.demo.local", "application server", "production", "high", 0),
    ("rh-api-01", "rivermill", "rh-api-01.demo.local", "API server", "production", "high", 1),
    ("rh-db-01", "rivermill", "rh-db-01.demo.local", "database", "production", "critical", 0),
    ("rh-web-01", "rivermill", "rh-web-01.demo.local", "web server", "production", "high", 1),
    ("rh-stage-01", "rivermill", "rh-stage-01.demo.local", "application server", "staging", "medium", 0),
    ("rh-admin-01", "rivermill", "rh-admin-01.demo.local", "admin workstation", "production", "medium", 0),
    ("cr-app-01", "cedar-ridge", "cr-app-01.demo.local", "application server", "production", "critical", 1),
    ("cr-api-01", "cedar-ridge", "cr-api-01.demo.local", "API server", "production", "high", 1),
    ("cr-db-01", "cedar-ridge", "cr-db-01.demo.local", "database", "production", "critical", 0),
    ("cr-worker-01", "cedar-ridge", "cr-worker-01.demo.local", "worker", "production", "medium", 0),
    ("cr-stage-01", "cedar-ridge", "cr-stage-01.demo.local", "application server", "staging", "medium", 0),
]

COMPONENT_ROWS = [
    ("component-log4j-affected", "ns-app-01", "org.apache.logging.log4j:log4j-core", "Maven", "2.14.1", "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"),
    ("component-log4j-fixed", "ns-app-02", "org.apache.logging.log4j:log4j-core", "Maven", "2.17.1", "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1"),
    ("component-guava", "ns-api-01", "com.google.guava:guava", "Maven", "31.0.1-jre", None),
    ("component-postgres", "ns-db-01", "postgresql", "PyPI", "42.7.2", "pkg:pypi/postgresql@42.7.2"),
    ("component-nginx", "ns-web-01", "nginx", "Maven", "1.24.0", None),
    ("component-requests", "ns-batch-01", "requests", "PyPI", "2.31.0", "pkg:pypi/requests@2.31.0"),
    ("component-jackson", "ns-stage-01", "com.fasterxml.jackson.core:jackson-databind", "Maven", "2.13.4", None),
    ("component-spring", "ns-admin-01", "org.springframework:spring-core", "Maven", "5.3.20", None),
    ("component-log4j-rh", "rh-app-01", "org.apache.logging.log4j:log4j-core", "Maven", "2.17.1", "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1"),
    ("component-commons", "rh-app-02", "org.apache.commons:commons-text", "Maven", "1.9", None),
    ("component-flask", "rh-api-01", "Flask", "PyPI", "2.2.2", "pkg:pypi/flask@2.2.2"),
    ("component-sqlalchemy", "rh-db-01", "SQLAlchemy", "PyPI", "1.4.45", None),
    ("component-tomcat", "rh-web-01", "org.apache.tomcat:tomcat-catalina", "Maven", "9.0.65", None),
    ("component-urllib", "rh-stage-01", "urllib3", "PyPI", "1.26.12", None),
    ("component-fastapi", "rh-admin-01", "fastapi", "PyPI", "0.103.1", None),
    ("component-log4j-cr", "cr-app-01", "org.apache.logging.log4j:log4j-core", "Maven", "2.17.1", "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1"),
    ("component-netty", "cr-api-01", "io.netty:netty-codec-http", "Maven", "4.1.86.Final", None),
    ("component-redis", "cr-db-01", "redis", "PyPI", "4.3.4", None),
    ("component-pillow", "cr-worker-01", "Pillow", "PyPI", "9.2.0", None),
    ("component-lodash", "cr-stage-01", "lodash", "npm", "4.17.20", "pkg:npm/lodash@4.17.20"),
]


def connect(path: str | Path | None = None) -> sqlite3.Connection:
    db_path = Path(path) if path else database_path()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(db_path, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA journal_mode = WAL")
    return connection


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _save_cache(
    connection: sqlite3.Connection,
    cache_key: str,
    source: str,
    payload: dict[str, Any],
    source_url: str,
    retrieved_at: str,
    mode: str,
    package_name: str | None = None,
    ecosystem: str | None = None,
    version: str | None = None,
) -> None:
    connection.execute(
        """INSERT INTO source_cache
           (cache_key, source, package_name, ecosystem, version, payload_json, source_url,
            retrieved_at, mode, status, last_error)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'available', NULL)
           ON CONFLICT(cache_key) DO UPDATE SET payload_json=excluded.payload_json,
            source_url=excluded.source_url, retrieved_at=excluded.retrieved_at,
            mode=excluded.mode, status='available', last_error=NULL""",
        (cache_key, source, package_name, ecosystem, version, json.dumps(payload), source_url,
         retrieved_at, mode),
    )


def initialize_database(path: str | Path | None = None) -> None:
    with connect(path) as connection:
        connection.executescript(SCHEMA)
        feed_columns = connection.execute("PRAGMA table_info(feed_state)").fetchall()
        last_success = next((column for column in feed_columns if column["name"] == "last_success_at"), None)
        if last_success is not None and last_success["notnull"]:
            connection.executescript(
                """ALTER TABLE feed_state RENAME TO feed_state_v1;
                   CREATE TABLE feed_state (
                     source TEXT PRIMARY KEY, status TEXT NOT NULL, mode TEXT NOT NULL,
                     checked_at TEXT NOT NULL, last_success_at TEXT, source_version TEXT,
                     last_error TEXT
                   );
                   INSERT INTO feed_state SELECT source,status,mode,checked_at,last_success_at,source_version,last_error
                     FROM feed_state_v1;
                   DROP TABLE feed_state_v1;"""
            )
        connection.executemany(
            "INSERT OR IGNORE INTO organizations(id,name,industry) VALUES(?,?,?)", ORGANIZATIONS
        )
        connection.executemany(
            """INSERT OR IGNORE INTO assets
               (id,organization_id,hostname,asset_type,environment,criticality,internet_exposed)
               VALUES(?,?,?,?,?,?,?)""",
            ASSET_ROWS,
        )
        connection.executemany(
            """INSERT OR IGNORE INTO components
               (id,asset_id,package_name,ecosystem,version,purl) VALUES(?,?,?,?,?,?)""",
            COMPONENT_ROWS,
        )
        _seed_fixtures(connection)


def _seed_fixtures(connection: sqlite3.Connection) -> None:
    osv_path = FIXTURE_ROOT / "osv_log4shell.json"
    kev_path = FIXTURE_ROOT / "cisa_kev_log4shell.json"
    if not osv_path.exists() or not kev_path.exists():
        return
    osv_fixture = json.loads(osv_path.read_text())
    kev_fixture = json.loads(kev_path.read_text())
    osv_record = osv_fixture["record"]
    osv_at = osv_fixture["retrieved_at"]
    kev_at = kev_fixture["retrieved_at"]
    query_key = "osv|Maven|org.apache.logging.log4j:log4j-core|2.14.1"
    _save_cache(
        connection, query_key, "OSV", {"vulns": [osv_record]}, osv_fixture["source"],
        osv_at, "demo_fixture", "org.apache.logging.log4j:log4j-core", "Maven", "2.14.1",
    )
    _save_cache(
        connection, "cisa-kev|catalog", "CISA KEV", kev_fixture,
        kev_fixture["source"], kev_at, "demo_fixture",
    )
    connection.execute(
        """INSERT OR IGNORE INTO advisories
           (advisory_id,aliases_json,summary,details,published,modified,source_url,raw_json)
           VALUES(?,?,?,?,?,?,?,?)""",
        (osv_record["id"], json.dumps(osv_record.get("aliases", [])),
         osv_record.get("summary", ""), osv_record.get("details", ""),
         osv_record.get("published"), osv_record.get("modified"), osv_fixture["source"],
         json.dumps(osv_record)),
    )
    for source, retrieved, version in (
        ("OSV", osv_at, osv_record.get("modified")),
        ("CISA KEV", kev_at, kev_fixture.get("catalogVersion")),
    ):
        connection.execute(
            """INSERT INTO feed_state(source,status,mode,checked_at,last_success_at,source_version,last_error)
               VALUES(?, 'available', 'demo_fixture', ?, ?, ?, NULL)
               ON CONFLICT(source) DO NOTHING""",
            (source, retrieved, retrieved, version),
        )

