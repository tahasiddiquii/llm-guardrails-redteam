"""PII / secret detection and redaction."""

from __future__ import annotations

from llm_guardrails.detectors.pii import detect_pii, redact


def test_detects_common_pii_types():
    text = "email me@x.com, call 415-555-0132, ssn 123-45-6789, host 10.0.0.1"
    types = {e.type for e in detect_pii(text)}
    assert {"EMAIL", "PHONE", "SSN", "IP"} <= types


def test_credit_card_requires_luhn():
    assert any(e.type == "CREDIT_CARD" for e in detect_pii("card 4242 4242 4242 4242"))
    assert not any(e.type == "CREDIT_CARD" for e in detect_pii("ref 1234 5678 9012 3456"))


def test_detects_aws_key():
    assert any(e.type == "AWS_KEY" for e in detect_pii("key AKIAIOSFODNN7EXAMPLE here"))


def test_redact_replaces_with_placeholder():
    out = redact("my email is me@x.com please")
    assert "me@x.com" not in out
    assert "[EMAIL]" in out


def test_no_false_positive_on_clean_text():
    assert detect_pii("the capital of France is Paris") == []
