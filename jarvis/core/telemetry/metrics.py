from __future__ import annotations

import math
import threading
from collections import deque
from dataclasses import dataclass
from typing import Any, Deque, Dict, Iterable, Optional, Tuple


def _tag_key(tags: Optional[Dict[str, Any]]) -> Tuple[Tuple[str, str], ...]:
    if not tags:
        return tuple()
    items = []
    for k, v in tags.items():
        if v is None:
            continue
        items.append((str(k), str(v)))
    return tuple(sorted(items))


@dataclass
class _Histogram:
    samples: Deque[float]


class RollingMetrics:
    """
    Thread-safe rolling metrics with bounded memory:
    - counters: int
    - gauges: any jsonable-ish scalar
    - histograms: last N float samples
    """

    def __init__(self, *, max_samples_per_histogram: int = 200):
        self.max_samples_per_histogram = max(10, int(max_samples_per_histogram))
        self._lock = threading.Lock()
        self._counters: Dict[Tuple[str, Tuple[Tuple[str, str], ...]], int] = {}
        self._gauges: Dict[Tuple[str, Tuple[Tuple[str, str], ...]], Any] = {}
        self._hist: Dict[Tuple[str, Tuple[Tuple[str, str], ...]], _Histogram] = {}

    def reset(self) -> None:
        with self._lock:
            self._counters.clear()
            self._gauges.clear()
            self._hist.clear()

    def inc(self, name: str, n: int = 1, tags: Optional[Dict[str, Any]] = None) -> None:
        k = (str(name), _tag_key(tags))
        with self._lock:
            self._counters[k] = int(self._counters.get(k, 0)) + int(n)

    def set_gauge(self, name: str, value: Any, tags: Optional[Dict[str, Any]] = None) -> None:
        k = (str(name), _tag_key(tags))
        with self._lock:
            self._gauges[k] = value

    def observe(self, name: str, value: float, tags: Optional[Dict[str, Any]] = None) -> None:
        k = (str(name), _tag_key(tags))
        v = float(value)
        with self._lock:
            if k not in self._hist:
                self._hist[k] = _Histogram(samples=deque(maxlen=self.max_samples_per_histogram))
            self._hist[k].samples.append(v)

    def snapshot(self) -> Dict[str, Any]:
        """
        Returns a compact summary:
        - counters: flattened keys
        - gauges: flattened keys
        - histograms: aggregated stats
        """
        with self._lock:
            counters = dict(self._counters)
            gauges = dict(self._gauges)
            hist = {k: list(v.samples) for k, v in self._hist.items()}

        def fmt_key(name: str, tagt: Tuple[Tuple[str, str], ...]) -> str:
            if not tagt:
                return name
            suffix = ",".join([f"{k}={v}" for k, v in tagt])
            return f"{name}{{{suffix}}}"

        out_c: Dict[str, int] = {fmt_key(k[0], k[1]): int(v) for k, v in counters.items()}
        out_g: Dict[str, Any] = {fmt_key(k[0], k[1]): v for k, v in gauges.items()}
        out_h: Dict[str, Dict[str, float]] = {}
        for (name, tagt), samples in hist.items():
            key = fmt_key(name, tagt)
            out_h[key] = _stats(samples)
        return {"counters": out_c, "gauges": out_g, "histograms": out_h}


def _percentile(sorted_vals: list[float], p: float) -> float:
    if not sorted_vals:
        return float("nan")
    if p <= 0:
        return sorted_vals[0]
    if p >= 100:
        return sorted_vals[-1]
    k = (len(sorted_vals) - 1) * (p / 100.0)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return sorted_vals[int(k)]
    d0 = sorted_vals[int(f)] * (c - k)
    d1 = sorted_vals[int(c)] * (k - f)
    return d0 + d1


def _stats(samples: Iterable[float]) -> Dict[str, float]:
    xs = [float(x) for x in samples]
    if not xs:
        return {"count": 0.0}
    xs.sort()
    count = float(len(xs))
    total = float(sum(xs))
    avg = total / count
    return {
        "count": count,
        "min": float(xs[0]),
        "max": float(xs[-1]),
        "avg": float(avg),
        "p50": float(_percentile(xs, 50)),
        "p95": float(_percentile(xs, 95)),
    }

