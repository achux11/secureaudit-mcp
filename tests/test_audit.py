"""Unit tests for the audit engine, PII scrubbing, privacy proxy and path guard."""

from pathlib import Path

import pytest

from secureaudit import audit_engine, pii, privacy_proxy
from secureaudit.paths import resolve_under_data_root
from secureaudit.scans import run_bundle_scan

DATA = Path(__file__).resolve().parent.parent / "sample_data"


def test_finds_cross_file_duplicate_invoices():
    result = audit_engine.find_duplicate_invoice_groups(
        [DATA / "erp_q3_export.csv", DATA / "legacy_billing_q3.csv"]
    )
    assert result["rows_loaded"] == 8
    assert result["cross_file_duplicate_groups"] == 2
    vendors = {g["match_key"]["vendor"] for g in result["groups"]}
    assert vendors == {"VEND-ACME-01", "VEND-NORTH-22"}


def test_flags_rbac_control_gaps():
    result = audit_engine.analyze_rbac_events(DATA / "rbac_audit_log.json")
    rules = sorted(f["rule"] for f in result["findings"])
    assert result["events"] == 4
    assert rules == ["HIGH_PRIV_EXTERNAL_ACTOR", "MISSING_CHANGE_TICKET", "MISSING_CHANGE_TICKET"]


def test_scrubs_email_card_and_ssn():
    out = pii.scrub_text("jdoe@employee.corp paid with 4111 1111 1111 1111, SSN 123-45-6789")
    assert "@" not in out and "4111" not in out and "123-45-6789" not in out
    assert "[REDACTED_EMAIL]" in out and "[REDACTED_CARD]" in out and "[REDACTED_SSN]" in out


def test_full_scan_output_contains_no_emails():
    bundle = run_bundle_scan()
    assert bundle["duplicate_group_count"] == 2
    assert bundle["rbac_finding_count"] == 3
    assert not pii.contains_suspected_pii(str(bundle["duplicates"]))


def test_privacy_proxy_builds_metadata_only_alert():
    alert = privacy_proxy.build_safe_alert("GENERIC_AUDIT", finding_count=5, extra_note="contact ap@north.example")
    ok, reason = privacy_proxy.validate_outbound_payload(alert)
    assert ok, reason
    assert "@" not in alert["text"]
    assert set(alert) == {"service", "alert_type", "finding_count", "reference", "text"}


def test_privacy_proxy_blocks_payload_with_pii():
    ok, _ = privacy_proxy.validate_outbound_payload({"text": "invoice for jdoe@employee.corp"})
    assert not ok


def test_rejects_unknown_alert_type():
    with pytest.raises(ValueError):
        privacy_proxy.build_safe_alert("EXFILTRATE_ALL", finding_count=1)


def test_blocks_paths_outside_data_root():
    with pytest.raises(PermissionError):
        resolve_under_data_root("/etc/passwd")


def test_random_reference_never_blocks_a_clean_alert():
    # Regression: hex references like "ab12..." used to match the IBAN pattern (~5% of alerts blocked).
    alert = privacy_proxy.build_safe_alert("GENERIC_AUDIT", finding_count=5, reference="ab12cdef34567890")
    assert privacy_proxy.validate_outbound_payload(alert)[0]
    blocked = sum(
        not privacy_proxy.validate_outbound_payload(privacy_proxy.build_safe_alert("RBAC_VIOLATION", finding_count=3))[0]
        for _ in range(2000)
    )
    assert blocked == 0
