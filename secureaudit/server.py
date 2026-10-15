"""SecureAudit AI — MCP server (resources + tools + privacy gateway)."""

from __future__ import annotations

import json
import os
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from secureaudit import alerts, audit_engine, pii, privacy_proxy
from secureaudit.paths import data_root, resolve_under_data_root

mcp = FastMCP("SecureAudit AI")


@mcp.resource("secureaudit://manifest")
def resource_manifest() -> str:
    root = data_root()
    files = sorted(p.name for p in root.iterdir() if p.is_file())
    meta = {
        "data_root": str(root),
        "datasets": files,
        "note": "Attach org CSV/JSON exports here or set SECUREAUDIT_DATA_ROOT to your vault path.",
    }
    return json.dumps(meta, indent=2)


@mcp.resource("secureaudit://policy/data-handling")
def resource_policy() -> str:
    return json.dumps(
        {
            "pii_scrubbing": "Outputs are passed through redaction for emails, card-like numbers, IBAN, SSN-like patterns.",
            "outbound_alerts": "Webhooks only accept compact metadata built via privacy_proxy.build_safe_alert patterns.",
            "path_allowlist": "Reads are restricted to SECUREAUDIT_DATA_ROOT unless SECUREAUDIT_ALLOW_ANY_PATH=1.",
        },
        indent=2,
    )


@mcp.resource("secureaudit://schemas/transactions_csv")
def resource_transaction_schema() -> str:
    return json.dumps(
        {
            "erp_shape": {
                "columns": ["invoice_id", "vendor_id", "amount", "invoice_date", "memo", "account_last4"],
            },
            "legacy_shape": {
                "columns": ["legacy_inv_no", "supplier_code", "amt_usd", "posted_on", "notes", "contact_email"],
            },
            "duplicate_match_logic": "Normalized tuple (vendor_id, amount, date) must match across rows from different files.",
        },
        indent=2,
    )


@mcp.tool()
def audit_duplicate_invoices(
    csv_file_names: str = "",
) -> str:
    """
    Detect duplicate billing lines across separate CSV exports (disjoint legacy systems).
    Pass comma-separated filenames under SECUREAUDIT_DATA_ROOT, or leave empty for bundled demos.
    """
    names = [x.strip() for x in csv_file_names.split(",") if x.strip()]
    if not names:
        names = ["erp_q3_export.csv", "legacy_billing_q3.csv"]
    paths = [resolve_under_data_root(n) for n in names]
    result = audit_engine.find_duplicate_invoice_groups(paths)
    safe = pii.scrub_jsonable(result)
    return json.dumps(safe, ensure_ascii=False)


@mcp.tool()
def audit_rbac_anomalies(json_file_name: str = "rbac_audit_log.json") -> str:
    """Analyze RBAC / permission-grant JSON logs for SOC2-style control gaps (external superuser, missing tickets)."""
    path = resolve_under_data_root(json_file_name)
    result = audit_engine.analyze_rbac_events(path)
    safe = pii.scrub_jsonable(result)
    return json.dumps(safe, ensure_ascii=False)


@mcp.tool()
def scrub_text_preview(text: str) -> str:
    """Return a PII-redacted copy of free-form text for safe model reasoning."""
    return pii.scrub_text(text)


@mcp.tool()
def send_compliance_alert(
    alert_type: str,
    finding_count: int,
    webhook_url: str = "",
    dry_run: bool = True,
    note: str = "",
) -> str:
    """
    Send a metadata-only webhook (Slack/Teams/PagerDuty-compatible JSON). Blocked if payload fails privacy proxy.
    Uses SECUREAUDIT_WEBHOOK_URL when webhook_url is empty. Toggle dry_run=false to POST for real.
    alert_type must be DUPLICATE_INVOICES, RBAC_VIOLATION, or GENERIC_AUDIT.
    """
    url = (webhook_url or os.environ.get("SECUREAUDIT_WEBHOOK_URL", "")).strip()
    payload = privacy_proxy.build_safe_alert(
        alert_type,
        finding_count=finding_count,
        extra_note=note or None,
    )
    if not url:
        out = {"ok": False, "error": "No webhook_url and SECUREAUDIT_WEBHOOK_URL unset", "payload": payload}
        return json.dumps(out, ensure_ascii=False)
    res = alerts.send_webhook(url, payload, dry_run=dry_run)
    return json.dumps({"payload": payload, **res}, ensure_ascii=False)


@mcp.tool()
def read_local_dataset_preview(file_name: str, max_lines: int = 12) -> str:
    """
    Read the first N lines of a dataset for structural context (still scrubbed).
    Use for schema confirmation without exporting full files to the model.
    """
    path: Path = resolve_under_data_root(file_name)
    max_lines = max(1, min(max_lines, 200))
    lines: list[str] = []
    with path.open(encoding="utf-8", errors="replace") as f:
        for _ in range(max_lines):
            line = f.readline()
            if not line:
                break
            lines.append(line.rstrip("\n"))
    preview = "\n".join(lines)
    return json.dumps(
        {
            "file": path.name,
            "preview_scrubbed": pii.scrub_text(preview),
            "truncated_to_lines": max_lines,
        },
        ensure_ascii=False,
    )


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
