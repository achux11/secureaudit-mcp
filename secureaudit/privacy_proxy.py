"""Privacy proxy: only metadata-only outbound payloads are permitted."""

from __future__ import annotations

import json
import re
import secrets
from typing import Any

from secureaudit.pii import contains_suspected_pii, scrub_text

_SAFE_ALERT_TYPES = frozenset({"DUPLICATE_INVOICES", "RBAC_VIOLATION", "GENERIC_AUDIT"})

_REF_PATTERN = re.compile(r"^[a-f0-9]{16}$")


def new_event_reference() -> str:
    return secrets.token_hex(8)


def build_safe_alert(
    alert_type: str,
    *,
    finding_count: int,
    reference: str | None = None,
    extra_note: str | None = None,
) -> dict[str, Any]:
    if alert_type not in _SAFE_ALERT_TYPES:
        raise ValueError(f"Unsupported alert_type: {alert_type}")
    ref = reference or new_event_reference()
    if not _REF_PATTERN.match(ref):
        raise ValueError("reference must be 16 lowercase hex chars")
    note = (extra_note or "").strip()
    if note and contains_suspected_pii(note):
        note = scrub_text(note)
    if contains_suspected_pii(note):
        note = ""
    message = (
        f"SecureAudit AI | {alert_type} | findings={finding_count} | ref={ref}"
    )
    if note:
        message = f"{message} | note={note}"
    return {
        "service": "SecureAudit AI",
        "alert_type": alert_type,
        "finding_count": int(finding_count),
        "reference": ref,
        "text": message,
    }


def validate_outbound_payload(payload: Any) -> tuple[bool, str]:
    try:
        raw = json.dumps(payload, ensure_ascii=False)
    except (TypeError, ValueError) as e:
        return False, f"Non-JSON-serializable payload: {e}"
    # The event reference is random hex we generate ourselves; it can resemble an
    # IBAN to the PII regexes, so mask it before scanning the rest of the payload.
    ref = payload.get("reference") if isinstance(payload, dict) else None
    scan = raw.replace(ref, "REF") if isinstance(ref, str) and _REF_PATTERN.match(ref) else raw
    if contains_suspected_pii(scan):
        return False, "Blocked: suspected PII or raw financial tokens in outbound payload"
    if len(raw) > 4000:
        return False, "Blocked: payload too large for metadata-only alert"
    return True, "ok"
