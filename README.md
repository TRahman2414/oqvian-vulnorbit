# OQVIAN VULNORBIT

A local-first vulnerability intelligence and risk prioritization demo.

> **Demo only:** this project does not provide production server monitoring, vulnerability prevention, or automated patching. Organizations, assets, and remediation actions are fictional.

The backend correlates a recorded package/version with OSV vulnerability evidence, enriches matching CVEs with CISA Known Exploited Vulnerabilities (KEV) data, applies explainable priority rules, and creates a local investigation case. A deterministic Log4Shell scenario works from saved source records without internet access. Live source refresh is an explicit action.

## Run locally

Requirements: Python 3.12 or newer and `uv`.

```bash
uv sync --dev
uv run uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000
```

The dashboard and API are available together at `http://127.0.0.1:8000`; OpenAPI documentation is at `/docs`. The SQLite database is created at `backend/data/vulnorbit.db` by default. Set `VULNORBIT_DB_PATH` to use a different local database path.

## First detection workflow

1. Start the local API.
2. `POST /api/detection/run` with `{}` to run the saved Log4Shell demo scenario.
3. Open `GET /api/findings` and inspect the CVE evidence and priority explanation.
4. Open `GET /api/cases` to see the persistent case.

`POST /api/intelligence/refresh` requests live OSV and CISA KEV data. If a refresh fails, the last successful local snapshot is kept and marked degraded/stale. The saved KEV fixture is a partial demo subset; it cannot establish that unrelated CVEs are absent from the full catalog.

## Tests

```bash
uv run pytest
```

The dashboard labels the inventory as synthetic and includes a local model connector placeholder. No model is connected in this demo. Source snapshots older than seven days are marked stale; the checked-in OSV and KEV snapshots are partial demonstration data.

## Current build status

The local demo includes a dashboard, synthetic inventory, saved Log4Shell detection scenario, source refresh controls, and case status tracking. Host agents, broad inventory ingestion, model inference, outbound notifications, and production remediation are not implemented.
