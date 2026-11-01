# OQVIAN VULNORBIT

A local-first vulnerability intelligence and risk prioritization demo.

> **Demo only:** this project does not provide production server monitoring, vulnerability prevention, or automated patching. Organizations, assets, and remediation actions are fictional.

OQVIAN VULNORBIT is a local analyst workspace for reviewing software vulnerabilities in an asset inventory. It correlates recorded package versions with OSV advisory evidence, enriches matching CVEs with CISA Known Exploited Vulnerabilities (KEV) data, explains its risk ranking, and creates investigation cases. The current demo uses fictional inventory and a saved Log4Shell scenario; it is designed to show the workflow, not to monitor real client systems.

## What the demo does

- Shows inventory, findings, case status, and source freshness in one local dashboard.
- Compares a component's package, ecosystem, and version against affected-version evidence.
- Adds CISA KEV context by CVE and combines it with fictional asset exposure and criticality to prioritize analyst review.
- Saves findings, evidence, scan history, and case updates in a local SQLite database.
- Lets an analyst refresh public intelligence feeds manually. Detection can also request a live refresh before it runs.

The complete workflow, decision rules, API routes, data handling, and current limitations are in [the product overview](docs/PRODUCT_OVERVIEW.md) and [the architecture notes](docs/ARCHITECTURE.md).

## Run locally

Requirements: Python 3.12 or newer and `uv`.

```bash
uv sync --dev
uv run uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000
```

The dashboard and API are available together at `http://127.0.0.1:8000`; OpenAPI documentation is at `/docs`. The SQLite database is created at `backend/data/vulnorbit.db` by default. Set `VULNORBIT_DB_PATH` to use a different local database path.

The server binds to loopback in this command, so the demo is for the local machine. It does not include sign-in or production deployment controls.

## Try the demo

1. Start the local API and open `http://127.0.0.1:8000`.
2. Select **Run detection (demo)**. The saved Log4Shell scenario creates an evidence-backed finding and investigation case.
3. Review the finding, asset context, and priority in the dashboard. For the full evidence and priority reasons, open `GET /api/findings` or the finding detail route.
4. Change the case status or assignee, then refresh to see that the update was saved.
5. Open **Integrations** to inspect source state. **Refresh intelligence sources** makes live requests to OSV and CISA KEV.
6. Use **Reset demo data** to restore the original fictional inventory and source fixtures.

Live source access is optional. The demo detection scenario works offline from saved records. If a live refresh fails, the last successful local snapshot is retained and its status is shown as degraded or stale.

## Tests

```bash
uv run pytest
```

The dashboard labels the inventory as synthetic and includes a local model connector placeholder. No model is connected in this demo. Source snapshots older than seven days are marked stale; the checked-in OSV and KEV snapshots are partial demonstration data.

## Current build status

The local demo includes a dashboard, synthetic inventory, saved Log4Shell detection scenario, source refresh controls, and case status tracking. Host agents, broad inventory ingestion, model inference, outbound notifications, and production remediation are not implemented.
