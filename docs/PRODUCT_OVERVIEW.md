# OQVIAN VULNORBIT Product Overview

## Purpose

OQVIAN VULNORBIT is a local-first vulnerability intelligence and risk triage demo. It shows how a security analyst can start with software inventory, check recorded package versions against vulnerability intelligence, decide which findings deserve attention first, and track the investigation in a case.

The demo is intended for product walkthroughs, architecture discussions, and early feedback from security, application security, and IT operations teams. Its inventory is fictional. It does not inspect a real network or claim that a customer environment is protected.

## Intended workflow

1. **Review the inventory.** The Assets view lists three fictional organizations and twenty sample hosts. Each asset includes software components with a package name, ecosystem, and recorded version.
2. **Run a detection pass.** The analyst starts the saved demo scenario from the dashboard, or calls `POST /api/detection/run`. Demo mode uses local source snapshots. Live mode refreshes intelligence first and then evaluates the inventory.
3. **Match package versions.** The backend compares package identity and version against OSV affected-package records. It reports a confirmed match only when the package and ecosystem match and the version is within an explicit affected list or a supported range. Unsupported or missing evidence stays unverified.
4. **Add exploitation context.** For CVEs in OSV aliases, the backend checks the CISA KEV catalog. A partial or stale catalog cannot establish that an absent CVE is not listed; that state remains unknown and requires review.
5. **Prioritize with asset context.** The demo combines match confidence, KEV status, source severity when available, fictional internet exposure, and fictional asset criticality. The API returns the reasons for each priority; the dashboard shows the resulting priority and source/asset context.
6. **Investigate and track.** A finding creates one persistent case. The dashboard lets analysts change its status and assignee; the API also supports adding notes. Re-running detection updates the same finding and case instead of creating duplicates for the same asset, component, and advisory.

## What an analyst sees

- **Overview:** organization, asset, finding, and case counts; the current priority summary; and the latest detection run.
- **Findings:** affected asset and component, CVE, match state, KEV state, priority, and evidence context.
- **Assets:** fictional organizations, hosts, criticality, exposure, and component counts.
- **Cases:** investigation status and assignee controls backed by the local API.
- **Integrations:** OSV and CISA KEV source freshness plus a generic local model connector placeholder.

The local model connector is not connected. Its control is intentionally disabled and there is no model inference or model-driven remediation in this build.

## Demo example

The saved scenario records Apache Log4j Core `2.14.1` on `ns-app-01.demo.local`. The OSV fixture identifies the version as affected and the CISA KEV fixture contains CVE-2021-44228. That fictional host is marked internet-exposed and business-critical, so the rules rank the finding as **P1 — Urgent review**. The dashboard exposes the source evidence and the reasons for that ranking.

The finding API contains the source evidence and priority reasons; the dashboard shows the finding, priority, and asset context. This is a demonstration of the workflow, not a claim about any real organization's assets. A fixed or non-matching version against this one advisory is not a general security assessment.

## Prioritization rules

- A non-confirmed match or stale/degraded OSV snapshot receives **Review required**.
- Unknown or stale KEV status receives **Review required** rather than being treated as “not listed.”
- A confirmed KEV-listed match is **P1** when the fictional asset is both internet-exposed and critical; otherwise it is **P2**.
- A confirmed non-KEV match with source-reported Critical or High severity is **P2**; other confirmed non-KEV matches are **P3**.

These deterministic rules are demo policy. They are not a universal risk standard and should be reviewed before any customer-specific use.

## Data and operating model

- The dashboard and FastAPI backend are served from one local process. The documented command binds to `127.0.0.1`.
- SQLite stores the sample inventory, source snapshots, feed state, findings, cases, scan runs, and audit events on the local machine.
- The bundled OSV record and CISA KEV fixture make the Log4Shell walkthrough work without network access. The KEV fixture contains only the Log4Shell record, and the saved OSV data is limited to the demonstration scenario; both are identified as partial.
- Live refresh is an explicit action. It requests OSV and CISA KEV data over the network. A failed request retains the last valid local snapshot, records the source error, and exposes degraded/stale status.
- Snapshots older than seven days are marked stale. The demo does not silently treat stale or partial data as full coverage.
- All organization, host, and asset-context records are synthetic. Do not enter customer inventory into this demo.

## Current scope and exclusions

This build demonstrates local inventory review, vulnerability matching, KEV enrichment, deterministic prioritization, source status, and analyst case tracking. It does not currently include customer inventory import, endpoint agents, network scanning, authentication, tenant isolation, a connected local model, notification delivery, automated patching, or production deployment hardening. The model connector is a UI placeholder only.

## Local use

See the root [README](../README.md) for setup. Once the server starts, use the dashboard at `http://127.0.0.1:8000` or the API documentation at `http://127.0.0.1:8000/docs`.

Useful routes:

| Route | Purpose |
| --- | --- |
| `GET /health` | Local demo process status |
| `GET /api/overview` | Dashboard counts and latest scan |
| `GET /api/assets` | Fictional inventory and software components |
| `POST /api/detection/run` | Run demo or live detection (`{"mode":"demo"}` or `{"mode":"live"}`) |
| `GET /api/findings` | List findings with priority and evidence |
| `GET /api/findings/{finding_id}` | Finding details and linked case |
| `GET /api/cases` | Investigation cases |
| `PATCH /api/cases/{case_id}` | Update case status or assignee |
| `POST /api/cases/{case_id}/notes` | Add an analyst note |
| `GET /api/intelligence/status` | Feed freshness and source state |
| `POST /api/intelligence/refresh` | Refresh OSV and CISA KEV snapshots |
| `POST /api/demo/reset` | Restore the original fictional demo state |

See [Architecture](ARCHITECTURE.md) for matching, source refresh, and risk-rule details.
