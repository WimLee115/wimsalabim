"""Ports analyzer — fully mocked, no real sockets.

We patch ``wimsalabim.analyzers.ports._is_open`` so each test can declare
which port numbers should be treated as open. The asyncio orchestration,
finding generation, severity bucketing, and grade calculation are all
exercised against this mock.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator

import pytest

from wimsalabim.analyzers.base import AnalysisContext
from wimsalabim.analyzers.ports import PortsAnalyzer


@pytest.fixture
def open_ports(monkeypatch: pytest.MonkeyPatch) -> Iterator[Callable[[Iterable[int]], None]]:
    """Return a setter; each test declares which TCP ports are 'open'.

    The setter may be called multiple times; the last call wins.
    """
    open_set: set[int] = set()

    async def fake_is_open(host: str, port: int, *, timeout: float) -> bool:
        return port in open_set

    monkeypatch.setattr("wimsalabim.analyzers.ports._is_open", fake_is_open)

    def setter(ports: Iterable[int]) -> None:
        open_set.clear()
        open_set.update(ports)

    yield setter


def _ctx(target: str = "127.0.0.1") -> AnalysisContext:
    return AnalysisContext(target=target, http=None)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_no_ports_open_grades_a(
    open_ports: Callable[[Iterable[int]], None],
) -> None:
    open_ports([])
    report = await PortsAnalyzer().analyze(_ctx())
    assert report.grade == "A"
    assert report.findings == []
    assert report.metadata["open_count"] == 0
    assert report.metadata["ports_scanned"] > 0


@pytest.mark.asyncio
async def test_only_safe_ports_open_grades_b(
    open_ports: Callable[[Iterable[int]], None],
) -> None:
    open_ports([80, 443])
    report = await PortsAnalyzer().analyze(_ctx())
    assert report.grade == "B"
    assert report.findings == []
    assert report.metadata["open_count"] == 2
    assert "80" in report.metadata["open_ports"]
    assert "443" in report.metadata["open_ports"]


@pytest.mark.asyncio
async def test_risky_high_severity_port_grades_c(
    open_ports: Callable[[Iterable[int]], None],
) -> None:
    # 3389 (RDP) and 6379 (Redis) are in the high-severity bucket.
    open_ports([3389, 6379])
    report = await PortsAnalyzer().analyze(_ctx())
    assert report.grade == "C"
    finding_ids = {f.id for f in report.findings}
    assert "ports.risky.3389" in finding_ids
    assert "ports.risky.6379" in finding_ids
    severities = {f.severity for f in report.findings}
    assert severities == {"high"}


@pytest.mark.asyncio
async def test_risky_medium_severity_port_grades_c(
    open_ports: Callable[[Iterable[int]], None],
) -> None:
    # 21 (FTP) and 3306 (MySQL) are medium-severity.
    open_ports([21, 3306])
    report = await PortsAnalyzer().analyze(_ctx())
    assert report.grade == "C"
    severities = {f.severity for f in report.findings}
    assert severities == {"medium"}


@pytest.mark.asyncio
async def test_mixed_safe_and_risky_grades_c_and_emits_findings(
    open_ports: Callable[[Iterable[int]], None],
) -> None:
    # Safe (443) shouldn't generate findings; risky (5900 VNC) should.
    open_ports([443, 5900])
    report = await PortsAnalyzer().analyze(_ctx())
    assert report.grade == "C"
    finding_ids = {f.id for f in report.findings}
    assert "ports.risky.5900" in finding_ids
    # 443 is safe — no finding for it
    assert not any("443" in fid for fid in finding_ids)


@pytest.mark.asyncio
async def test_finding_carries_cwe_and_remediation(
    open_ports: Callable[[Iterable[int]], None],
) -> None:
    open_ports([3389])
    report = await PortsAnalyzer().analyze(_ctx())
    assert len(report.findings) == 1
    f = report.findings[0]
    assert f.cwe == "CWE-200"
    assert f.remediation is not None
    assert "3389" in f.remediation
    assert f.source.target == "127.0.0.1:3389"


@pytest.mark.asyncio
async def test_metadata_aggregates(
    open_ports: Callable[[Iterable[int]], None],
) -> None:
    open_ports([22, 80, 443, 3389])
    report = await PortsAnalyzer().analyze(_ctx())
    assert report.metadata["open_count"] == 4
    assert report.metadata["ports_scanned"] >= 23  # default port set is at least this
    open_str = report.metadata["open_ports"]
    assert isinstance(open_str, str)
    for p in (22, 80, 443, 3389):
        assert str(p) in open_str
    risky_str = report.metadata["risky_open"]
    assert isinstance(risky_str, str)
    assert "3389" in risky_str
    assert "22" not in risky_str  # 22 is safe in our taxonomy
    assert "80" not in risky_str


@pytest.mark.asyncio
async def test_severity_classifier_low_band(
    open_ports: Callable[[Iterable[int]], None],
) -> None:
    """A port that is in _RISKY_PORTS but in the low-severity bucket."""
    from wimsalabim.analyzers.ports import _severity_for_port

    # 8080 is not risky in our taxonomy, _severity_for_port returns 'low'
    # for ports that aren't in the high/medium sets.
    assert _severity_for_port(8080) == "low"
    assert _severity_for_port(3389) == "high"
    assert _severity_for_port(21) == "medium"


@pytest.mark.asyncio
async def test_class_attributes_set_by_decorator() -> None:
    assert PortsAnalyzer.name == "ports"
    assert PortsAnalyzer.legal_class == "active"
    assert "tcp" in PortsAnalyzer.capabilities.network


@pytest.mark.asyncio
async def test_critical_severity_port_grades_f(
    monkeypatch: pytest.MonkeyPatch,
    open_ports: Callable[[Iterable[int]], None],
) -> None:
    """Cover the defensive grade==F branch by injecting a critical severity."""

    def fake_severity(port: int) -> str:
        return "critical" if port == 3389 else "low"

    monkeypatch.setattr("wimsalabim.analyzers.ports._severity_for_port", fake_severity)
    open_ports([3389])
    report = await PortsAnalyzer().analyze(_ctx())
    assert report.grade == "F"
    assert report.findings[0].severity == "critical"


@pytest.mark.asyncio
async def test_is_open_against_real_loopback_socket() -> None:
    """Exercise the real `_is_open` against a one-shot listening socket.

    This is the only test that touches a real socket; it covers both the
    open and connection-refused branches without faking ``asyncio``.
    """
    import asyncio
    import contextlib
    import socket

    from wimsalabim.analyzers.ports import _is_open

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setblocking(False)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    open_port: int = listener.getsockname()[1]

    async def accept_once() -> None:
        loop = asyncio.get_running_loop()
        with contextlib.suppress(OSError, asyncio.TimeoutError):
            client_sock, _ = await loop.sock_accept(listener)
            client_sock.close()

    accept_task = asyncio.create_task(accept_once())
    try:
        assert await _is_open("127.0.0.1", open_port, timeout=2.0) is True
    finally:
        listener.close()
        accept_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await accept_task

    # Listener gone → connection refused → False
    assert await _is_open("127.0.0.1", open_port, timeout=1.0) is False
