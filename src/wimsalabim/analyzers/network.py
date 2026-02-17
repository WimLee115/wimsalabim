"""Network quality analyzers - latency, jitter, packet loss, bandwidth, congestion. rootmap:WimLee115"""

from __future__ import annotations

import socket
import ssl
import statistics
import struct
import time
from dataclasses import dataclass, field


@dataclass
class LatencyResult:
    target: str
    samples: list[float] = field(default_factory=list)
    min_ms: float = 0.0
    max_ms: float = 0.0
    avg_ms: float = 0.0
    median_ms: float = 0.0
    stddev_ms: float = 0.0
    packet_loss_pct: float = 0.0
    jitter_ms: float = 0.0

    @property
    def quality(self) -> str:
        if self.avg_ms < 50 and self.jitter_ms < 10 and self.packet_loss_pct == 0:
            return "excellent"
        if self.avg_ms < 100 and self.jitter_ms < 30 and self.packet_loss_pct < 2:
            return "good"
        if self.avg_ms < 200 and self.jitter_ms < 50 and self.packet_loss_pct < 5:
            return "fair"
        return "poor"


@dataclass
class BandwidthEstimate:
    download_estimate_mbps: float = 0.0
    method: str = ""
    transfer_size_bytes: int = 0
    transfer_time_ms: float = 0.0


@dataclass
class ConnectionStability:
    score: float = 0.0
    samples: int = 0
    variance: float = 0.0
    trend: str = ""
    stable: bool = True


@dataclass
class CongestionPrediction:
    congestion_score: float = 0.0
    risk_level: str = "low"
    indicators: list[str] = field(default_factory=list)
    predicted_degradation_pct: float = 0.0


@dataclass
class NetworkReport:
    target: str
    available: bool = False
    latency: LatencyResult = field(default_factory=lambda: LatencyResult(target=""))
    bandwidth: BandwidthEstimate = field(default_factory=BandwidthEstimate)
    stability: ConnectionStability = field(default_factory=ConnectionStability)
    congestion: CongestionPrediction = field(default_factory=CongestionPrediction)
    issues: list[str] = field(default_factory=list)
    grade: str = "N/A"


def analyze_network(target: str, samples: int = 10) -> NetworkReport:
    report = NetworkReport(target=target)
    report.latency = LatencyResult(target=target)

    latencies = _measure_latency(target, samples)

    if not latencies:
        report.issues.append("Could not measure latency - target unreachable")
        return report

    report.available = True
    report.latency.samples = latencies
    report.latency.min_ms = round(min(latencies), 2)
    report.latency.max_ms = round(max(latencies), 2)
    report.latency.avg_ms = round(statistics.mean(latencies), 2)
    report.latency.median_ms = round(statistics.median(latencies), 2)

    if len(latencies) > 1:
        report.latency.stddev_ms = round(statistics.stdev(latencies), 2)

    lost = samples - len(latencies)
    report.latency.packet_loss_pct = round((lost / samples) * 100, 1)

    report.latency.jitter_ms = _calculate_jitter(latencies)

    report.bandwidth = _estimate_bandwidth(target)
    report.stability = _assess_stability(latencies)
    report.congestion = _predict_congestion(report.latency, report.stability)

    _generate_issues(report)
    report.grade = _calculate_grade(report)

    return report


def _measure_latency(target: str, count: int = 10) -> list[float]:
    """Measure TCP connection latency to port 443 or 80."""
    latencies = []

    for port in (443, 80):
        for _ in range(count):
            try:
                start = time.perf_counter()
                sock = socket.create_connection((target, port), timeout=5)
                elapsed = (time.perf_counter() - start) * 1000
                sock.close()
                latencies.append(round(elapsed, 2))
            except (socket.timeout, ConnectionRefusedError, OSError):
                continue

        if latencies:
            break

    return latencies


def _calculate_jitter(latencies: list[float]) -> float:
    """Calculate jitter as mean of consecutive differences."""
    if len(latencies) < 2:
        return 0.0

    diffs = [abs(latencies[i + 1] - latencies[i]) for i in range(len(latencies) - 1)]
    return round(statistics.mean(diffs), 2)


def _estimate_bandwidth(target: str) -> BandwidthEstimate:
    """Estimate bandwidth by measuring TLS handshake + small transfer timing."""
    estimate = BandwidthEstimate(method="TLS handshake timing")

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED

        start = time.perf_counter()
        with socket.create_connection((target, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                ssock.sendall(
                    f"HEAD / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n".encode()
                )
                data = ssock.recv(4096)
                elapsed = (time.perf_counter() - start) * 1000

                estimate.transfer_size_bytes = len(data)
                estimate.transfer_time_ms = round(elapsed, 2)

                if elapsed > 0:
                    bytes_per_sec = (len(data) / (elapsed / 1000))
                    estimate.download_estimate_mbps = round(
                        (bytes_per_sec * 8) / 1_000_000, 2
                    )
    except Exception:
        pass

    return estimate


def _assess_stability(latencies: list[float]) -> ConnectionStability:
    """Assess connection stability from latency samples."""
    stability = ConnectionStability(samples=len(latencies))

    if len(latencies) < 3:
        stability.score = 0.5
        stability.trend = "insufficient data"
        return stability

    stability.variance = round(statistics.variance(latencies), 2)

    mean = statistics.mean(latencies)
    cv = (statistics.stdev(latencies) / mean) if mean > 0 else 0

    stability.score = round(max(0, min(1, 1 - cv)), 3)
    stability.stable = cv < 0.3

    half = len(latencies) // 2
    first_half = statistics.mean(latencies[:half])
    second_half = statistics.mean(latencies[half:])

    if second_half > first_half * 1.15:
        stability.trend = "degrading"
    elif second_half < first_half * 0.85:
        stability.trend = "improving"
    else:
        stability.trend = "stable"

    return stability


def _predict_congestion(latency: LatencyResult, stability: ConnectionStability) -> CongestionPrediction:
    """Predict network congestion based on observed metrics."""
    prediction = CongestionPrediction()
    score = 0.0
    indicators = []

    if latency.avg_ms > 150:
        score += 0.3
        indicators.append(f"High average latency: {latency.avg_ms}ms")
    elif latency.avg_ms > 80:
        score += 0.15
        indicators.append(f"Moderate latency: {latency.avg_ms}ms")

    if latency.jitter_ms > 30:
        score += 0.25
        indicators.append(f"High jitter: {latency.jitter_ms}ms")
    elif latency.jitter_ms > 15:
        score += 0.1
        indicators.append(f"Moderate jitter: {latency.jitter_ms}ms")

    if latency.packet_loss_pct > 0:
        score += 0.3
        indicators.append(f"Packet loss detected: {latency.packet_loss_pct}%")

    if not stability.stable:
        score += 0.15
        indicators.append("Connection instability detected")

    if stability.trend == "degrading":
        score += 0.1
        indicators.append("Latency trend is degrading")

    if latency.max_ms > latency.avg_ms * 3:
        score += 0.1
        indicators.append(f"Latency spikes detected: max {latency.max_ms}ms vs avg {latency.avg_ms}ms")

    prediction.congestion_score = round(min(1.0, score), 3)
    prediction.indicators = indicators

    if score >= 0.7:
        prediction.risk_level = "critical"
        prediction.predicted_degradation_pct = round(score * 60, 1)
    elif score >= 0.4:
        prediction.risk_level = "high"
        prediction.predicted_degradation_pct = round(score * 40, 1)
    elif score >= 0.2:
        prediction.risk_level = "medium"
        prediction.predicted_degradation_pct = round(score * 20, 1)
    else:
        prediction.risk_level = "low"
        prediction.predicted_degradation_pct = 0.0

    return prediction


def _generate_issues(report: NetworkReport) -> None:
    lat = report.latency

    if lat.packet_loss_pct > 5:
        report.issues.append(f"High packet loss: {lat.packet_loss_pct}%")
    elif lat.packet_loss_pct > 0:
        report.issues.append(f"Packet loss detected: {lat.packet_loss_pct}%")

    if lat.jitter_ms > 50:
        report.issues.append(f"Excessive jitter: {lat.jitter_ms}ms")
    elif lat.jitter_ms > 20:
        report.issues.append(f"Elevated jitter: {lat.jitter_ms}ms")

    if lat.avg_ms > 200:
        report.issues.append(f"High latency: {lat.avg_ms}ms average")

    if not report.stability.stable:
        report.issues.append("Unstable connection detected")

    if report.congestion.risk_level in ("high", "critical"):
        report.issues.append(
            f"Congestion risk: {report.congestion.risk_level} "
            f"(predicted {report.congestion.predicted_degradation_pct}% degradation)"
        )


def _calculate_grade(report: NetworkReport) -> str:
    if not report.available:
        return "F"

    score = 100
    lat = report.latency

    if lat.avg_ms > 200:
        score -= 30
    elif lat.avg_ms > 100:
        score -= 15
    elif lat.avg_ms > 50:
        score -= 5

    score -= min(30, lat.packet_loss_pct * 6)
    score -= min(20, lat.jitter_ms * 0.4)

    if not report.stability.stable:
        score -= 15

    score -= min(15, report.congestion.congestion_score * 15)

    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"
