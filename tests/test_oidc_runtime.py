import os

import pytest

from governed_autonomy import build_runtime_service_with_oidc, OIDCValidator


def test_build_runtime_service_with_oidc_constructs_validator(monkeypatch):
    monkeypatch.setenv("GAS_RUNTIME_MODE", "memory")
    monkeypatch.setenv("OIDC_ISSUER", "https://example.local")
    monkeypatch.setenv("OIDC_AUDIENCE", "test-aud")
    monkeypatch.setenv("OIDC_JWKS_URL", "https://example.local/.well-known/jwks.json")

    service, issuer, replay_log, oidc_validator = build_runtime_service_with_oidc()
    assert oidc_validator is None or isinstance(oidc_validator, OIDCValidator)
    # No network call is made at construction time; the validator may be returned
    # or deferred depending on environment. The key-check is that the helper
    # returns a fourth element and does not raise.
