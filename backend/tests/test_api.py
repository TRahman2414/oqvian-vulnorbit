from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient

from app.main import create_app
from app import services
from app.adapters.cisa_kev import CISAKEVError
from app.adapters.osv import SourceError
from app.database import connect


def test_log4shell_detection_is_persistent_and_idempotent(tmp_path):
    client = TestClient(create_app(tmp_path / "demo.sqlite"))

    health = client.get("/health")
    assert health.status_code == 200
    assert health.json()["mode"] == "local_demo"

    overview = client.get("/api/overview").json()
    assert overview["organizations"] == 3
    assert overview["assets"] == 20

    first_run = client.post("/api/detection/run", json={}).json()
    assert first_run["status"] == "complete"
    assert first_run["findings"] == 1

    findings = client.get("/api/findings").json()
    assert len(findings) == 1
    finding = findings[0]
    assert finding["cve_id"] == "CVE-2021-44228"
    assert finding["match_state"] == "confirmed_affected"
    assert finding["kev_status"] == "listed"
    assert finding["priority"] == "P1 — Urgent review"
    assert finding["evidence"]["osv"]["version"] == "2.14.1"
    assert finding["evidence"]["cisa_kev"]["entry"]["cveID"] == "CVE-2021-44228"
    detail = client.get(f"/api/findings/{finding['id']}").json()
    assert detail["case"]["notes"] == []

    cases_before = client.get("/api/cases").json()
    assert len(cases_before) == 1
    second_run = client.post("/api/detection/run", json={}).json()
    assert second_run["findings"] == 1
    assert len(client.get("/api/findings").json()) == 1
    cases_after = client.get("/api/cases").json()
    assert len(cases_after) == 1
    assert cases_after[0]["id"] == cases_before[0]["id"]


def test_case_updates_and_notes_are_persisted(tmp_path):
    client = TestClient(create_app(tmp_path / "case.sqlite"))
    client.post("/api/detection/run", json={})
    case = client.get("/api/cases").json()[0]

    updated = client.patch(
        f"/api/cases/{case['id']}",
        json={"status": "in_progress", "assignee": "Demo Analyst"},
    )
    assert updated.status_code == 200
    assert updated.json()["status"] == "in_progress"

    note = client.post(
        f"/api/cases/{case['id']}/notes", json={"text": "Review upgrade path."}
    )
    assert note.status_code == 200
    assert note.json()["notes"][0]["text"] == "Review upgrade path."


def test_demo_reset_removes_findings_but_keeps_fictional_inventory(tmp_path):
    db_path = tmp_path / "reset.sqlite"
    client = TestClient(create_app(db_path))
    client.post("/api/detection/run", json={})
    result = client.post("/api/demo/reset")
    assert result.status_code == 200
    assert client.get("/api/findings").json() == []
    assert len(client.get("/api/assets").json()) == 20
    assert {row["source"] for row in client.get("/api/intelligence/status").json()} == {"OSV", "CISA KEV"}


def test_dashboard_is_served_by_the_local_api(tmp_path):
    client = TestClient(create_app(tmp_path / "dashboard.sqlite"))

    response = client.get("/")

    assert response.status_code == 200
    assert "OQVIAN VULNORBIT" in response.text
    assert "Synthetic demo labels" in response.text


def test_old_source_snapshots_are_marked_stale(tmp_path):
    db_path = tmp_path / "stale.sqlite"
    create_app(db_path)
    old_time = (datetime.now(UTC) - timedelta(days=8)).isoformat()

    with connect(db_path) as connection:
        connection.execute(
            "UPDATE source_cache SET retrieved_at=? WHERE cache_key='cisa-kev|catalog'",
            (old_time,),
        )
        _, kev_state, _ = services._kev_index(connection)

    statuses = {row["source"]: row["status"] for row in services.intelligence_status(str(db_path))}
    assert kev_state == "stale"
    assert statuses["CISA KEV"] == "stale"


def test_failed_live_refresh_keeps_last_valid_snapshots(tmp_path, monkeypatch):
    db_path = tmp_path / "refresh.sqlite"
    create_app(db_path)

    def fail_osv(*args, **kwargs):
        raise SourceError("source unavailable in test")

    def fail_cisa(*args, **kwargs):
        raise CISAKEVError("source unavailable in test")

    monkeypatch.setattr(services.OSVClient, "query_batch", fail_osv)
    monkeypatch.setattr(services.CISAKEVClient, "fetch", fail_cisa)
    result = services.refresh_intelligence(str(db_path))

    assert result["sources"]["OSV"]["status"] == "degraded"
    assert result["sources"]["CISA KEV"]["status"] == "degraded"
    with connect(db_path) as connection:
        cache_count = connection.execute("SELECT COUNT(*) FROM source_cache").fetchone()[0]
        states = {row["source"]: dict(row) for row in connection.execute("SELECT * FROM feed_state")}
    assert cache_count == 2
    assert states["OSV"]["status"] == "degraded"
    assert states["OSV"]["last_success_at"]
    assert states["CISA KEV"]["last_success_at"]


def test_partial_demo_kev_fixture_does_not_claim_unlisted_for_absent_cves(tmp_path):
    db_path = tmp_path / "partial-kev.sqlite"
    create_app(db_path)

    with connect(db_path) as connection:
        entries, status, version = services._kev_index(connection)

    assert status == "partial"
    assert version
    assert "CVE-2021-44228" in entries
    assert "CVE-2024-00001" not in entries


def test_successful_osv_refresh_replaces_old_advisory_snapshot(tmp_path, monkeypatch):
    db_path = tmp_path / "replace-osv.sqlite"
    create_app(db_path)

    monkeypatch.setattr(services.OSVClient, "query_batch", lambda self, queries: [[] for _ in queries])
    fixture = services.CISAKEVClient
    monkeypatch.setattr(fixture, "fetch", lambda self: {
        "catalogVersion": "test",
        "dateReleased": "2026-11-01T00:00:00Z",
        "vulnerabilities": [],
    })

    result = services.refresh_intelligence(str(db_path))

    assert result["sources"]["OSV"]["status"] == "available"
    with connect(db_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM advisories").fetchone()[0] == 0
