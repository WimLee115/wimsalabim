"""Async port scanner with service detection."""

from __future__ import annotations

import asyncio
import socket
from dataclasses import dataclass, field


TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 119, 135, 139, 143, 161, 162,
    389, 443, 445, 465, 514, 587, 636, 993, 995, 1080, 1433, 1434,
    1521, 1723, 2049, 2082, 2083, 2086, 2087, 3306, 3389, 5432, 5900,
    5985, 5986, 6379, 6443, 8000, 8008, 8080, 8443, 8888, 9090, 9200,
    9300, 27017, 27018,
]

SERVICE_MAP = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCbind", 119: "NNTP", 135: "MSRPC",
    139: "NetBIOS", 143: "IMAP", 161: "SNMP", 162: "SNMP-trap",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 514: "Syslog",
    587: "SMTP-sub", 636: "LDAPS", 993: "IMAPS", 995: "POP3S",
    1080: "SOCKS", 1433: "MSSQL", 1434: "MSSQL-UDP", 1521: "Oracle",
    1723: "PPTP", 2049: "NFS", 2082: "cPanel", 2083: "cPanel-SSL",
    2086: "WHM", 2087: "WHM-SSL", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM", 5986: "WinRM-SSL",
    6379: "Redis", 6443: "K8s-API", 8000: "HTTP-alt", 8008: "HTTP-alt",
    8080: "HTTP-proxy", 8443: "HTTPS-alt", 8888: "HTTP-alt",
    9090: "Prometheus", 9200: "Elasticsearch", 9300: "ES-transport",
    27017: "MongoDB", 27018: "MongoDB",
}

RISKY_PORTS = {
    21, 23, 135, 139, 445, 161, 162, 1433, 1434, 3306, 3389,
    5432, 5900, 6379, 9200, 27017, 27018, 1521, 111, 514, 2049,
}


@dataclass
class PortResult:
    port: int
    state: str
    service: str
    banner: str = ""
    risk: str = "info"


@dataclass
class PortScanReport:
    target: str
    ip_address: str = ""
    open_ports: list[PortResult] = field(default_factory=list)
    closed_count: int = 0
    filtered_count: int = 0
    scan_time: float = 0.0

    @property
    def open_count(self) -> int:
        return len(self.open_ports)

    @property
    def risky_ports(self) -> list[PortResult]:
        return [p for p in self.open_ports if p.risk in ("high", "critical")]


async def _grab_banner(ip: str, port: int, timeout: float = 2.0) -> str:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        try:
            banner = await asyncio.wait_for(reader.read(1024), timeout=timeout)
            return banner.decode("utf-8", errors="replace").strip()[:200]
        except (asyncio.TimeoutError, Exception):
            return ""
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
    except Exception:
        return ""


async def _scan_port(
    ip: str, port: int, timeout: float = 1.5
) -> tuple[int, bool]:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return port, True
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return port, False


def _assess_risk(port: int) -> str:
    if port in (23, 21, 161, 162, 514):
        return "critical"
    if port in RISKY_PORTS:
        return "high"
    if port in (8080, 8443, 8888, 9090, 8000, 8008):
        return "medium"
    return "low"


async def scan_ports(
    target: str,
    ports: list[int] | None = None,
    timeout: float = 1.5,
    concurrency: int = 100,
) -> PortScanReport:
    import time

    start = time.monotonic()
    ports_to_scan = ports or TOP_PORTS

    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        return PortScanReport(target=target)

    semaphore = asyncio.Semaphore(concurrency)

    async def _limited_scan(port: int) -> tuple[int, bool]:
        async with semaphore:
            return await _scan_port(ip, port, timeout)

    tasks = [_limited_scan(p) for p in ports_to_scan]
    results = await asyncio.gather(*tasks)

    open_ports = []
    closed = 0

    for port, is_open in results:
        if is_open:
            service = SERVICE_MAP.get(port, "unknown")
            risk = _assess_risk(port)
            banner = await _grab_banner(ip, port)
            open_ports.append(PortResult(
                port=port, state="open", service=service,
                banner=banner, risk=risk,
            ))
        else:
            closed += 1

    open_ports.sort(key=lambda p: p.port)
    elapsed = time.monotonic() - start

    return PortScanReport(
        target=target,
        ip_address=ip,
        open_ports=open_ports,
        closed_count=closed,
        scan_time=round(elapsed, 2),
    )
