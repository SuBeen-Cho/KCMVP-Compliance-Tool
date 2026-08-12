"""API-free synthetic benchmark for the sealed LEA round shadow chain."""
from __future__ import annotations

import json
import shutil
import statistics
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from app.services.clang_straightline_reaching_def import verify_and_bind_preprocessing
from app.services.lea_round_shadow_chain import evaluate_lea_round_shadow_chain
from app.services.preprocessing_provenance import capture_trusted_preprocessing

SECRET = b"synthetic-lea-shadow-chain-secret-v1"
GOOD = """typedef unsigned int uint32_t;
void lea_round_graph_fixture(uint32_t *restrict out, const uint32_t *restrict in,
 const uint32_t *restrict rk) {
 out[0]=(((in[0]^rk[0])+(in[1]^rk[1]))<<9)|(((in[0]^rk[0])+(in[1]^rk[1]))>>23);
 out[1]=(((in[1]^rk[2])+(in[2]^rk[3]))>>5)|(((in[1]^rk[2])+(in[2]^rk[3]))<<27);
 out[2]=(((in[2]^rk[4])+(in[3]^rk[5]))>>3)|(((in[2]^rk[4])+(in[3]^rk[5]))<<29);
 out[3]=in[0];
}
void synthetic_caller(void) {
 uint32_t out[4], in[4], rk[6];
 lea_round_graph_fixture(out,in,rk);
}
"""


def _capture(source: str, *, analyze_after_capture: str | None = None) -> dict[str, Any]:
    compiler = shutil.which("clang")
    if compiler is None:
        return {"state": "unknown", "reason": "clang_unavailable",
                "structural_chain_complete": False, "semantic_authorization": 0}
    with tempfile.TemporaryDirectory(prefix="lea-chain-capture-") as directory:
        root = Path(directory)
        path = root / "unit.c"
        path.write_text(source, encoding="utf-8")
        captured = capture_trusted_preprocessing(
            source_path=path, compiler=compiler, arguments=[], cwd=root,
            environment={"LC_ALL": "C"}, allowlisted_environment={"LC_ALL"},
            candidate_id="synthetic-chain", rule_id="LEA-031",
            runtime_secret=SECRET,
        )
        # Replay the sealed argv byte-for-byte; Clang may expose its invoked
        # path in predefined output, so a symlink spelling is not equivalent.
        proc = subprocess.run(captured["private_capture"]["argv"], cwd=root,
                              env={"LC_ALL": "C"}, capture_output=True, check=False)
        analyzed = proc.stdout.decode("utf-8")
        binding = verify_and_bind_preprocessing(
            envelope=captured["envelope"], runtime_secret=SECRET,
            expected=captured["envelope"]["provenance"],
            private_capture=captured["private_capture"], analyzed_source=analyzed,
        )
    if analyze_after_capture is not None:
        analyzed += analyze_after_capture
    return evaluate_lea_round_shadow_chain(analyzed, preprocessing_binding=binding)


def fixtures() -> list[tuple[str, str, bool]]:
    return [
        ("exact", GOOD, True),
        ("wrong_rotate", GOOD.replace("<<9", "<<8", 1), False),
        ("aliased_arrays", GOOD.replace("(out,in,rk)", "(out,out,rk)"), False),
        ("pointer_arithmetic", GOOD.replace("(out,in,rk)", "(out,in+1,rk)"), False),
        ("undersized_round_key", GOOD.replace("rk[6]", "rk[5]"), False),
    ]


def run_benchmark(*, latency_samples: int = 3) -> dict[str, Any]:
    if latency_samples < 1:
        raise ValueError("latency_samples_must_be_positive")
    rows = []
    for name, source, expected in fixtures():
        result = _capture(source)
        observed = result.get("structural_chain_complete") is True
        rows.append({"case": name, "expected_complete": expected,
                     "observed_complete": observed, "correct": observed == expected,
                     "state": result.get("state"), "reason": result.get("reason")})
    tampered = _capture(GOOD, analyze_after_capture="\nint post_capture_tamper;\n")
    rows.append({"case": "post_capture_source_tamper", "expected_complete": False,
                 "observed_complete": tampered.get("structural_chain_complete") is True,
                 "correct": tampered.get("structural_chain_complete") is not True,
                 "state": tampered.get("state"), "reason": tampered.get("reason")})
    samples = []
    for _ in range(latency_samples):
        started = time.perf_counter_ns()
        _capture(GOOD)
        samples.append((time.perf_counter_ns() - started) / 1_000_000)
    return {
        "schema_version": "1.0",
        "benchmark": "lea-round-sealed-shadow-chain-synthetic",
        "population": {"cases": len(rows), "mutation_attacks": len(rows) - 1,
                       "latency_samples": latency_samples},
        "results": rows,
        "metrics": {"correct": sum(row["correct"] for row in rows),
                    "false_accepts": sum(not row["expected_complete"] and row["observed_complete"]
                                         for row in rows),
                    "false_rejects": sum(row["expected_complete"] and not row["observed_complete"]
                                         for row in rows)},
        "latency_ms_end_to_end": {"mean": round(statistics.mean(samples), 3),
                                  "median": round(statistics.median(samples), 3),
                                  "max": round(max(samples), 3)},
        "api_calls": 0, "semantic_authorization": 0,
        "fact_state": "unknown",
        "claim_limit": "Synthetic structural chain only; caller algorithm/applicability and GT unproved.",
    }


if __name__ == "__main__":
    print(json.dumps(run_benchmark(), ensure_ascii=False, indent=2, sort_keys=True))
