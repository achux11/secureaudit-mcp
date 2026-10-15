"""Shared scan orchestration for CLI demo, web UI, and tools."""

from __future__ import annotations

import os
from typing import Any

from secureaudit import pii, privacy_proxy
from secureaudit.audit_engine import analyze_rbac_events, find_duplicate_invoice_groups
from secureaudit.paths import data_root, resolve_under_data_root


def run_bundle_scan(selected_files: list[str] | None = None) -> dict[str, Any]:
    names = (
        ["erp_q3_export.csv", "legacy_billing_q3.csv", "rbac_audit_log.json"]
        if selected_files is None
        else selected_files
    )
    resolved = [resolve_under_data_root(n) for n in names]
    txn_paths = [p for p in resolved if p.suffix.lower() != ".json"]
    rbac_paths = [p for p in resolved if p.suffix.lower() == ".json"]

    if txn_paths:
        dups = find_duplicate_invoice_groups(txn_paths)
    else:
        dups = {
            "files_scanned": [],
            "rows_loaded": 0,
            "cross_file_duplicate_groups": 0,
            "groups": [],
        }

    rbac_findings: list[dict[str, Any]] = []
    rbac_events_total = 0
    rbac_files_scanned: list[str] = []
    for path in rbac_paths:
        one = analyze_rbac_events(path)
        rbac_events_total += int(one.get("events", 0))
        rbac_files_scanned.append(str(one.get("file", path.name)))
        for f in one.get("findings", []):
            if isinstance(f, dict):
                merged = dict(f)
                merged["file"] = path.name
                rbac_findings.append(merged)
    rbac = {
        "files": rbac_files_scanned,
        "events": rbac_events_total,
        "findings": rbac_findings,
        "finding_count": len(rbac_findings),
    }
    dup_n = int(dups.get("cross_file_duplicate_groups", 0))
    rbac_n = int(rbac.get("finding_count", 0))
    return {
        "duplicates": pii.scrub_jsonable(dups),
        "rbac": pii.scrub_jsonable(rbac),
        "duplicate_group_count": dup_n,
        "rbac_finding_count": rbac_n,
        "selected_files": names,
        "selected_transaction_files": [p.name for p in txn_paths],
        "selected_rbac_files": [p.name for p in rbac_paths],
        "data_root": str(data_root()),
    }


def alert_type_and_count(dup_n: int, rbac_n: int) -> tuple[str, int]:
    if dup_n and rbac_n:
        return "GENERIC_AUDIT", dup_n + rbac_n
    if dup_n:
        return "DUPLICATE_INVOICES", dup_n
    if rbac_n:
        return "RBAC_VIOLATION", rbac_n
    return "GENERIC_AUDIT", 0


def build_alert_for_scan(dup_n: int, rbac_n: int) -> dict[str, Any] | None:
    if not dup_n and not rbac_n:
        return None
    kind, n = alert_type_and_count(dup_n, rbac_n)
    return privacy_proxy.build_safe_alert(kind, finding_count=max(n, 1))


def send_alert_from_scan(
    dup_n: int,
    rbac_n: int,
    *,
    webhook_url: str = "",
    dry_run: bool = True,
) -> dict[str, Any]:
    from secureaudit.alerts import send_webhook

    payload = build_alert_for_scan(dup_n, rbac_n)
    if payload is None:
        return {"ok": True, "skipped": True, "reason": "No findings"}
    url = (webhook_url or os.environ.get("SECUREAUDIT_WEBHOOK_URL", "")).strip()
    if not url:
        return {
            "ok": False,
            "error": "No webhook URL (enter in UI or set SECUREAUDIT_WEBHOOK_URL).",
            "payload": payload,
            "sent": False,
        }
    result = send_webhook(url, payload, dry_run=dry_run)
    return {"payload": payload, **result}
