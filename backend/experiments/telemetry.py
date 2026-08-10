"""Deterministic timing, token, and cost accounting for experiment runs."""
from __future__ import annotations

import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Iterator


@dataclass
class Telemetry:
    phases_s: dict[str, float] = field(default_factory=dict)
    calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0

    @contextmanager
    def phase(self, name: str) -> Iterator[None]:
        start = time.perf_counter()
        try:
            yield
        finally:
            self.phases_s[name] = self.phases_s.get(name, 0.0) + time.perf_counter() - start

    def cost(self, input_usd_per_million: float, output_usd_per_million: float) -> float:
        return (
            self.input_tokens * input_usd_per_million
            + self.output_tokens * output_usd_per_million
        ) / 1_000_000

    def as_dict(self, pricing: dict[str, object]) -> dict[str, object]:
        return {
            "phases_s": self.phases_s,
            "total_s": sum(self.phases_s.values()),
            "calls": self.calls,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "pricing_snapshot": pricing,
            "estimated_cost_usd": self.cost(
                float(pricing["input_usd_per_million"]),
                float(pricing["output_usd_per_million"]),
            ),
        }
