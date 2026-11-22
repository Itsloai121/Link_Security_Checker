"""Tiny in-process metrics registry with Prometheus text exposition (USBA §15.2). Thread-safe, label-bounded."""
from __future__ import annotations

import threading
from collections import defaultdict

_BUCKETS = (0.5, 1, 2, 5, 10, 20, 40, 80)


def _key(labels: dict[str, str] | None) -> tuple:
    return tuple(sorted((labels or {}).items()))


class Metrics:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[str, dict[tuple, float]] = defaultdict(lambda: defaultdict(float))
        self._hist: dict[str, dict[tuple, list[float]]] = defaultdict(dict)
        self._gauges: dict[str, float] = {}
        self._help: dict[str, str] = {}

    def describe(self, name: str, text: str) -> None:
        self._help[name] = text

    def inc(self, name: str, labels: dict[str, str] | None = None, value: float = 1.0) -> None:
        with self._lock:
            series = self._counters[name]
            if len(series) < 500 or _key(labels) in series:  # cardinality guard
                series[_key(labels)] += value

    def set_gauge(self, name: str, value: float) -> None:
        with self._lock:
            self._gauges[name] = value

    def observe(self, name: str, seconds: float, labels: dict[str, str] | None = None) -> None:
        with self._lock:
            row = self._hist[name].setdefault(_key(labels), [0.0] * (len(_BUCKETS) + 2))
            for i, b in enumerate(_BUCKETS):
                if seconds <= b:
                    row[i] += 1
            row[-2] += 1  # count
            row[-1] += seconds  # sum

    def value(self, name: str, labels: dict[str, str] | None = None) -> float:
        with self._lock:
            return self._counters[name].get(_key(labels), 0.0)

    def render(self) -> str:
        def fmt(labels: tuple, extra: str = "") -> str:
            items = [f'{k}="{v}"' for k, v in labels] + ([extra] if extra else [])
            return "{" + ",".join(items) + "}" if items else ""

        lines: list[str] = []
        with self._lock:
            for name, series in sorted(self._counters.items()):
                lines += [f"# HELP {name} {self._help.get(name, name)}", f"# TYPE {name} counter"]
                lines += [f"{name}{fmt(k)} {v:g}" for k, v in series.items()]
            for name, value in sorted(self._gauges.items()):
                lines += [f"# HELP {name} {self._help.get(name, name)}", f"# TYPE {name} gauge", f"{name} {value:g}"]
            for name, series in sorted(self._hist.items()):
                lines += [f"# HELP {name} {self._help.get(name, name)}", f"# TYPE {name} histogram"]
                for k, row in series.items():
                    for i, b in enumerate(_BUCKETS):
                        lines.append(name + "_bucket" + fmt(k, 'le="' + str(b) + '"') + f" {row[i]:g}")
                    lines.append(name + "_bucket" + fmt(k, 'le="+Inf"') + f" {row[-2]:g}")
                    lines += [f"{name}_count{fmt(k)} {row[-2]:g}", f"{name}_sum{fmt(k)} {row[-1]:.3f}"]
        return "\n".join(lines) + "\n"
