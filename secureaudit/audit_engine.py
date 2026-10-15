"""Local audit logic: cross-system duplicate invoices and RBAC anomalies."""

from __future__ import annotations

import csv
import json
from collections import defaultdict
from datetime import datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any


def _parse_amount(raw: str) -> Decimal:
    s = (raw or "").strip().replace(",", "")
    if not s:
        raise InvalidOperation
    return Decimal(s)


def _parse_date(raw: str) -> str:
    s = (raw or "").strip()[:10]
    datetime.strptime(s, "%Y-%m-%d")
    return s


def _normalize_row_erp(row: dict[str, str]) -> dict[str, str]:
    return {
        "invoice_ref": row.get("invoice_id", "").strip(),
        "vendor": row.get("vendor_id", "").strip().upper(),
        "amount": str(_parse_amount(row.get("amount", "0"))),
        "date": _parse_date(row.get("invoice_date", "")),
        "source_hint": "erp",
    }


def _normalize_row_legacy(row: dict[str, str]) -> dict[str, str]:
    return {
        "invoice_ref": row.get("legacy_inv_no", "").strip(),
        "vendor": row.get("supplier_code", "").strip().upper(),
        "amount": str(_parse_amount(row.get("amt_usd", "0"))),
        "date": _parse_date(row.get("posted_on", "")),
        "source_hint": "legacy",
    }


def _detect_format(headers: list[str]) -> str:
    h = {x.strip().lower() for x in headers}
    if "invoice_id" in h and "vendor_id" in h:
        return "erp"
    if "legacy_inv_no" in h and "supplier_code" in h:
        return "legacy"
    return "unknown"


def load_normalized_transactions(path: Path) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    with path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        headers = reader.fieldnames or []
        fmt = _detect_format(list(headers))
        for i, row in enumerate(reader, start=2):
            try:
                if fmt == "erp":
                    norm = _normalize_row_erp(row)
                elif fmt == "legacy":
                    norm = _normalize_row_legacy(row)
                else:
                    norm = {
                        "invoice_ref": str(i),
                        "vendor": (row.get("vendor_id") or row.get("supplier_code") or "").upper(),
                        "amount": str(_parse_amount(row.get("amount") or row.get("amt_usd") or "0")),
                        "date": _parse_date(row.get("invoice_date") or row.get("posted_on") or "1970-01-01"),
                        "source_hint": "generic",
                    }
            except (InvalidOperation, ValueError):
                continue
            norm["source_file"] = path.name
            norm["row_index"] = str(i)
            out.append(norm)
    return out


def find_duplicate_invoice_groups(paths: list[Path]) -> dict[str, Any]:
    by_key: dict[tuple[str, str, str], list[dict[str, str]]] = defaultdict(list)
    all_rows: list[dict[str, str]] = []
    for p in paths:
        rows = load_normalized_transactions(p)
        all_rows.extend(rows)
        for r in rows:
            key = (r["vendor"], r["amount"], r["date"])
            by_key[key].append(r)

    duplicate_groups = []
    for key, rows in by_key.items():
        if len(rows) < 2:
            continue
        files = sorted({x["source_file"] for x in rows})
        if len(files) < 2:
            continue
        duplicate_groups.append(
            {
                "match_key": {"vendor": key[0], "amount": key[1], "date": key[2]},
                "occurrences": len(rows),
                "sources": [
                    {"file": r["source_file"], "row": r["row_index"], "invoice_ref": r["invoice_ref"]}
                    for r in rows
                ],
            }
        )

    return {
        "files_scanned": [p.name for p in paths],
        "rows_loaded": len(all_rows),
        "cross_file_duplicate_groups": len(duplicate_groups),
        "groups": duplicate_groups,
    }


def _actor_domain(actor: str) -> str:
    if "@" not in actor:
        return ""
    return actor.split("@", 1)[1].lower()


def analyze_rbac_events(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("RBAC audit log must be a JSON array")
    findings: list[dict[str, Any]] = []
    trusted_suffixes = ("internal.corp",)

    for i, ev in enumerate(data):
        if not isinstance(ev, dict):
            continue
        actor = str(ev.get("actor", ""))
        action = str(ev.get("action", "")).lower()
        role = str(ev.get("role", "")).lower()
        ticket = str(ev.get("ticket", "")).strip()
        resource = str(ev.get("resource", ""))

        domain = _actor_domain(actor)
        is_internal = domain.endswith(trusted_suffixes)

        if role == "superuser" and not is_internal:
            findings.append(
                {
                    "rule": "HIGH_PRIV_EXTERNAL_ACTOR",
                    "index": i,
                    "severity": "critical",
                    "detail": "Superuser grant from non-internal domain",
                }
            )
        if action in ("role_granted", "permission_changed") and role in ("superuser", "db_owner"):
            if not ticket:
                findings.append(
                    {
                        "rule": "MISSING_CHANGE_TICKET",
                        "index": i,
                        "severity": "high",
                        "detail": "Sensitive role without linked change ticket",
                    }
                )

    return {
        "file": path.name,
        "events": len(data),
        "findings": findings,
        "finding_count": len(findings),
    }
