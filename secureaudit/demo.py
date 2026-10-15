"""Command-line demo: run local audits without an MCP client (for recordings / CI)."""

from __future__ import annotations

import argparse
import json
import os

from secureaudit.paths import data_root
from secureaudit.scans import run_bundle_scan, send_alert_from_scan


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="SecureAudit AI local demo runner")
    p.add_argument(
        "--webhook",
        default="",
        help="Optional HTTPS webhook URL (metadata-only payload). Uses SECUREAUDIT_WEBHOOK_URL if unset.",
    )
    p.add_argument(
        "--send-alert",
        action="store_true",
        help="POST compliance alert if --webhook or env URL is set (otherwise dry-run only).",
    )
    args = p.parse_args(argv)

    print(f"SECUREAUDIT_DATA_ROOT -> {data_root()}\n")

    bundle = run_bundle_scan()
    print("=== Duplicate invoice scan (scrubbed) ===")
    print(json.dumps(bundle["duplicates"], indent=2))
    print("\n=== RBAC anomaly scan (scrubbed) ===")
    print(json.dumps(bundle["rbac"], indent=2))

    dup_n = int(bundle["duplicate_group_count"])
    rbac_n = int(bundle["rbac_finding_count"])
    url = (args.webhook or os.environ.get("SECUREAUDIT_WEBHOOK_URL", "")).strip()

    if dup_n or rbac_n:
        dry = not (args.send_alert and bool(url))
        print("\n=== Privacy proxy + webhook ===")
        res = send_alert_from_scan(dup_n, rbac_n, webhook_url=url, dry_run=dry)
        print(json.dumps(res, indent=2))
    else:
        print("\n(No findings; webhook demo skipped.)")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
