"""Webhook delivery with privacy proxy enforcement."""

from __future__ import annotations

import json
import os
from typing import Any

import httpx

from secureaudit.privacy_proxy import validate_outbound_payload

_DEFAULT_TIMEOUT = 15.0


def send_webhook(
    url: str,
    payload: dict[str, Any],
    *,
    dry_run: bool = False,
) -> dict[str, Any]:
    ok, reason = validate_outbound_payload(payload)
    if not ok:
        return {"ok": False, "error": reason, "sent": False}
    if dry_run:
        return {"ok": True, "sent": False, "dry_run": True, "payload": payload}
    headers = {"Content-Type": "application/json"}
    token = os.environ.get("SECUREAUDIT_WEBHOOK_SECRET", "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    try:
        with httpx.Client(timeout=_DEFAULT_TIMEOUT) as client:
            r = client.post(url, content=body, headers=headers)
            r.raise_for_status()
    except httpx.HTTPError as e:
        return {"ok": False, "error": str(e), "sent": False}
    return {"ok": True, "sent": True, "status_code": r.status_code}
