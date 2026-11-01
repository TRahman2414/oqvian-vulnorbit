# Architecture

## Local data flow

```text
fictional asset inventory
  -> package + ecosystem + recorded version
  -> cached OSV advisory and affected-version evidence
  -> CISA KEV enrichment by CVE alias
  -> deterministic priority + evidence trail
  -> persisted finding, investigation case, and audit event
```

FastAPI serves the local API. SQLite stores the inventory, validated source snapshots, findings, cases, and audit events. No host collector, network scanner, model inference, external notification, or patch command is part of this demo.

## Match rules

- A result is confirmed only when the package name and ecosystem match an OSV affected entry and the recorded version is inside an explicit affected version list or a supported ecosystem range.
- Numeric Maven ranges are evaluated as inclusive introduced and exclusive fixed boundaries; `last_affected` is inclusive. Unsupported version syntax or range types stay unverified.
- A non-match is scoped to that advisory. It does not make the asset or package generally secure.
- Findings are deduplicated by asset, component, and canonical CVE when available; otherwise by advisory ID.
- A case is one-to-one with a finding in this first slice. Re-running detection updates the same finding and case.

## Source handling

The checked-in OSV record is the full public advisory for CVE-2021-44228. The checked-in CISA KEV fixture contains only that CVE, so it is explicitly treated as partial. Live refresh validates responses and writes each source snapshot transactionally. A failure updates source health but retains the last successful snapshot. Data older than seven days is marked stale.

The OSV query adapter follows pagination. Batch queries fetch full advisory records when the batch response provides only identifiers. CISA KEV is used only as CVE exploitation evidence; its due date is preserved as source metadata and is not treated as a customer deadline.

## Risk rules

Match confidence and priority are separate. Confirmed + KEV-listed + internet-exposed + critical asset yields P1. Confirmed KEV matches without both context factors yield P2. A confirmed non-KEV match uses source-provided severity when available. Unknown or stale KEV status yields “Review required” rather than an assumed negative.
