"""PII scrubbing for text and structured payloads."""

from __future__ import annotations

import copy
import json
import re
from typing import Any

# Conservative patterns for auditing demos — extend for production DLP.
_EMAIL = re.compile(
    r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}\b",
    re.IGNORECASE,
)
_CC_LIKE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
_SSN_LIKE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_IBAN_LIKE = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b", re.IGNORECASE)
_ACCOUNT_RAW = re.compile(r"\b\d{8,17}\b")

_REPLACEMENTS: list[tuple[re.Pattern[str], str]] = [
    (_EMAIL, "[REDACTED_EMAIL]"),
    (_SSN_LIKE, "[REDACTED_SSN]"),
    (_IBAN_LIKE, "[REDACTED_IBAN]"),
    (_CC_LIKE, "[REDACTED_CARD]"),
    (_ACCOUNT_RAW, "[REDACTED_NUMERIC_ID]"),
]


def scrub_text(text: str) -> str:
    out = text
    for pat, rep in _REPLACEMENTS:
        out = pat.sub(rep, out)
    return out


def contains_suspected_pii(text: str) -> bool:
    if scrub_text(text) != text:
        return True
    return False


def scrub_value(v: Any) -> Any:
    if isinstance(v, str):
        return scrub_text(v)
    if isinstance(v, list):
        return [scrub_value(x) for x in v]
    if isinstance(v, dict):
        return {k: scrub_value(val) for k, val in v.items()}
    return v


def scrub_jsonable(obj: Any) -> Any:
    return scrub_value(copy.deepcopy(obj))


def scrub_json_str(payload: str) -> str:
    data = json.loads(payload)
    return json.dumps(scrub_value(data), ensure_ascii=False)
