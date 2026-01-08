"""
Telemetry & Health Monitoring (local-only).

This subsystem collects:
- Subsystem health (active checks + passive error signals)
- Rolling metrics (counters/histograms/gauges)
- Local resource usage (CPU/RAM/Disk, best-effort GPU)

It never exports telemetry over the network.
"""

from jarvis.core.telemetry.manager import TelemetryManager

__all__ = ["TelemetryManager"]

