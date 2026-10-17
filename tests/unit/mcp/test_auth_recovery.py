"""Regression coverage for the optional browser recovery handoff.

These tests never contact Google or expose real cookies.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from notebooklm.mcp._auth_recovery import _validate_storage, _write_storage


def _candidate(email: str = "owner@example.com", *, complete: bool = True) -> bytes:
    cookies = [{"name": "SID", "value": "test", "domain": ".google.com"}]
    if complete:
        cookies.append(
            {"name": "__Secure-1PSIDTS", "value": "test", "domain": ".google.com"}
        )
    return json.dumps(
        {
            "cookies": cookies,
            "origins": [],
            "notebooklm": {"version": 1, "account": {"authuser": 0, "email": email}},
        }
    ).encode("utf-8")


def test_valid_storage_shape_and_account() -> None:
    result = _validate_storage(_candidate(), "OWNER@example.com")
    assert result["notebooklm"]["account"]["email"] == "owner@example.com"


@pytest.mark.parametrize(
    "payload",
    [
        b"not json",
        b"[]",
        b'{"cookies": []}',
        _candidate(complete=False),
        _candidate("other@example.com"),
    ],
)
def test_invalid_or_wrong_account_rejected(payload: bytes) -> None:
    with pytest.raises(ValueError):
        _validate_storage(payload, "owner@example.com")


def test_storage_replace_preserves_valid_json(tmp_path: Path) -> None:
    dest = tmp_path / "profiles" / "server" / "storage_state.json"
    dest.parent.mkdir(parents=True)
    dest.write_text("original")
    _write_storage(dest, _candidate())
    assert json.loads(dest.read_text())["notebooklm"]["account"]["email"] == (
        "owner@example.com"
    )
    assert not list(dest.parent.glob(".notebooklm-reauth-*"))


def test_empty_payload_is_rejected() -> None:
    with pytest.raises(ValueError):
        _validate_storage(b"", "owner@example.com")
