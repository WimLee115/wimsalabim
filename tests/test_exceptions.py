"""Exception hierarchy — message formatting + isinstance chain."""

from __future__ import annotations

import pytest

from wimsalabim.core.exceptions import (
    AnalyzerError,
    AnalyzerTimeout,
    ConfigError,
    NetworkError,
    WimsalabimError,
)


def test_analyzer_error_carries_name() -> None:
    e = AnalyzerError(analyzer="tls", message="bad cert")
    assert e.analyzer == "tls"
    assert "[tls]" in str(e)
    assert "bad cert" in str(e)


def test_analyzer_timeout_is_analyzer_error() -> None:
    e = AnalyzerTimeout(analyzer="x", message="exceeded")
    assert isinstance(e, AnalyzerError)
    assert isinstance(e, WimsalabimError)


def test_network_error_attributes() -> None:
    e = NetworkError(kind="dns", target="example.com", message="resolver failure")
    assert e.kind == "dns"
    assert e.target == "example.com"
    assert "[dns]" in str(e)
    assert "example.com" in str(e)


def test_config_error_is_wimsalabim_error() -> None:
    e = ConfigError("bad value")
    assert isinstance(e, WimsalabimError)


def test_can_be_raised_and_caught() -> None:
    with pytest.raises(WimsalabimError):
        raise NetworkError(kind="x", target="y", message="z")
