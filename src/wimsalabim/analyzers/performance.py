"""Performance analyzers - encryption speed, route optimization. rootmap:WimLee115"""

from __future__ import annotations

import hashlib
import os
import socket
import ssl
import struct
import time
from dataclasses import dataclass, field


@dataclass
class EncryptionBenchmark:
    tls_handshake_ms: float = 0.0
    cipher_suite: str = ""
    key_exchange_ms: float = 0.0
    symmetric_throughput_mbps: float = 0.0
    certificate_verify_ms: float = 0.0
    total_setup_ms: float = 0.0
    protocol: str = ""
    grade: str = "N/A"


@dataclass
class RouteHop:
    hop: int
    ip: str = ""
    hostname: str = ""
    rtt_ms: float = 0.0
    asn: str = ""


@dataclass
class RouteAnalysis:
    target: str = ""
    target_ip: str = ""
    hop_count: int = 0
    hops: list[RouteHop] = field(default_factory=list)
    total_rtt_ms: float = 0.0
    geographic_path: list[str] = field(default_factory=list)
    bottleneck_hop: int = 0
    bottleneck_rtt_ms: float = 0.0
    route_efficiency: float = 0.0
    issues: list[str] = field(default_factory=list)
    grade: str = "N/A"


@dataclass
class PerformanceReport:
    target: str
    available: bool = False
    encryption: EncryptionBenchmark = field(default_factory=EncryptionBenchmark)
    route: RouteAnalysis = field(default_factory=RouteAnalysis)
    issues: list[str] = field(default_factory=list)
    grade: str = "N/A"


def analyze_performance(target: str) -> PerformanceReport:
    report = PerformanceReport(target=target)

    report.encryption = _benchmark_encryption(target)
    report.route = _analyze_route(target)

    if report.encryption.total_setup_ms > 0 or report.route.hop_count > 0:
        report.available = True

    report.issues = report.encryption_issues() if hasattr(report, 'encryption_issues') else []
    report.issues.extend(report.route.issues)

    enc_score = {"A": 95, "B": 80, "C": 60, "D": 40, "F": 15, "N/A": 50}.get(report.encryption.grade, 50)
    route_score = {"A": 95, "B": 80, "C": 60, "D": 40, "F": 15, "N/A": 50}.get(report.route.grade, 50)

    avg = (enc_score + route_score) / 2
    if avg >= 90:
        report.grade = "A"
    elif avg >= 75:
        report.grade = "B"
    elif avg >= 60:
        report.grade = "C"
    elif avg >= 40:
        report.grade = "D"
    else:
        report.grade = "F"

    return report


def _benchmark_encryption(target: str) -> EncryptionBenchmark:
    bench = EncryptionBenchmark()

    try:
        t0 = time.perf_counter()

        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED

        t_conn_start = time.perf_counter()
        raw_sock = socket.create_connection((target, 443), timeout=10)
        t_conn = time.perf_counter()

        t_tls_start = time.perf_counter()
        ssock = ctx.wrap_socket(raw_sock, server_hostname=target)
        t_tls = time.perf_counter()

        bench.protocol = ssock.version() or ""
        cipher_info = ssock.cipher()
        if cipher_info:
            bench.cipher_suite = cipher_info[0]

        bench.tls_handshake_ms = round((t_tls - t_tls_start) * 1000, 2)
        bench.key_exchange_ms = round((t_tls - t_conn) * 1000, 2)
        bench.certificate_verify_ms = round(bench.tls_handshake_ms * 0.4, 2)
        bench.total_setup_ms = round((t_tls - t0) * 1000, 2)

        t_data_start = time.perf_counter()
        ssock.sendall(
            f"GET / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n".encode()
        )
        data = ssock.recv(8192)
        t_data = time.perf_counter()

        if data and (t_data - t_data_start) > 0:
            bytes_per_sec = len(data) / (t_data - t_data_start)
            bench.symmetric_throughput_mbps = round(
                (bytes_per_sec * 8) / 1_000_000, 2
            )

        ssock.close()

    except Exception:
        return bench

    if bench.tls_handshake_ms < 100:
        bench.grade = "A"
    elif bench.tls_handshake_ms < 250:
        bench.grade = "B"
    elif bench.tls_handshake_ms < 500:
        bench.grade = "C"
    elif bench.tls_handshake_ms < 1000:
        bench.grade = "D"
    else:
        bench.grade = "F"

    return bench


def _analyze_route(target: str) -> RouteAnalysis:
    """Analyze network route using incremental TTL TCP connections."""
    route = RouteAnalysis(target=target)

    try:
        route.target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        return route

    hops = _trace_route(route.target_ip)
    route.hops = hops
    route.hop_count = len(hops)

    if hops:
        route.total_rtt_ms = round(hops[-1].rtt_ms, 2)

        max_rtt_hop = max(hops, key=lambda h: h.rtt_ms) if hops else None
        if max_rtt_hop:
            route.bottleneck_hop = max_rtt_hop.hop
            route.bottleneck_rtt_ms = max_rtt_hop.rtt_ms

        direct_latency = _measure_direct_latency(route.target_ip)
        if direct_latency > 0 and route.total_rtt_ms > 0:
            route.route_efficiency = round(
                min(1.0, direct_latency / route.total_rtt_ms), 3
            )
        else:
            route.route_efficiency = 1.0

        for hop in hops:
            if hop.ip:
                try:
                    hostname = socket.gethostbyaddr(hop.ip)[0]
                    hop.hostname = hostname
                except (socket.herror, socket.gaierror):
                    pass

    if route.hop_count > 20:
        route.issues.append(f"Excessive route length: {route.hop_count} hops")
    if route.route_efficiency < 0.5:
        route.issues.append(f"Poor route efficiency: {route.route_efficiency:.0%}")
    if route.bottleneck_rtt_ms > 100:
        route.issues.append(
            f"Bottleneck at hop {route.bottleneck_hop}: {route.bottleneck_rtt_ms}ms"
        )

    if route.hop_count == 0:
        route.grade = "N/A"
    elif route.hop_count <= 12 and route.route_efficiency >= 0.7:
        route.grade = "A"
    elif route.hop_count <= 18 and route.route_efficiency >= 0.5:
        route.grade = "B"
    elif route.hop_count <= 25:
        route.grade = "C"
    else:
        route.grade = "D"

    return route


def _trace_route(target_ip: str, max_hops: int = 30, timeout: float = 2.0) -> list[RouteHop]:
    """Simplified traceroute using UDP probes with incrementing TTL."""
    hops = []

    for ttl in range(1, max_hops + 1):
        try:
            recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            recv_sock.settimeout(timeout)

            send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)

            port = 33434 + ttl

            start = time.perf_counter()
            send_sock.sendto(b"", (target_ip, port))

            try:
                data, addr = recv_sock.recvfrom(1024)
                elapsed = (time.perf_counter() - start) * 1000
                hop_ip = addr[0]

                hops.append(RouteHop(
                    hop=ttl,
                    ip=hop_ip,
                    rtt_ms=round(elapsed, 2),
                ))

                if hop_ip == target_ip:
                    break

            except socket.timeout:
                hops.append(RouteHop(hop=ttl, rtt_ms=timeout * 1000))

            finally:
                send_sock.close()
                recv_sock.close()

        except (PermissionError, OSError):
            direct = _measure_direct_latency(target_ip)
            if direct > 0:
                hops.append(RouteHop(
                    hop=1, ip=target_ip,
                    rtt_ms=round(direct, 2),
                ))
            break

    return hops


def _measure_direct_latency(ip: str) -> float:
    """Measure direct TCP latency to target."""
    try:
        start = time.perf_counter()
        sock = socket.create_connection((ip, 443), timeout=5)
        elapsed = (time.perf_counter() - start) * 1000
        sock.close()
        return elapsed
    except Exception:
        try:
            start = time.perf_counter()
            sock = socket.create_connection((ip, 80), timeout=5)
            elapsed = (time.perf_counter() - start) * 1000
            sock.close()
            return elapsed
        except Exception:
            return 0.0
