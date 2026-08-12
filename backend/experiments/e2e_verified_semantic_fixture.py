"""End-to-end, API-free shadow benchmark for sealed structural evidence."""
from __future__ import annotations

import json
import statistics
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from app.services.clang_straightline_reaching_def import (
    prove_straightline_output_reaching_defs,
    verify_and_bind_preprocessing,
)
from app.services.lea001_clang_block_proof import prove_lea001_block_semantics
from app.services.lea001_rhs_coverage_proof import prove_lea001_rhs_coverage
from app.services.preprocessing_provenance import capture_trusted_preprocessing

FIXTURE = """\
void lea_encrypt_block(const unsigned char *input, unsigned char *output) {
  for (unsigned int i = 0; i < 16; ++i) { output[i] = input[i]; }
}
void schedule(unsigned round, unsigned *out) {
  out[0] = round + 1;
  out[1] = round + 2;
}
"""
SECRET = b"synthetic-e2e-fixture-secret-32-bytes!!"


def _preprocessed(private: dict[str, Any]) -> str:
    process = subprocess.run(
        private["argv"], cwd=private["cwd"], env=dict(private["environment"]),
        capture_output=True, check=False, timeout=30,
    )
    if process.returncode != 0:
        raise RuntimeError("synthetic_preprocessing_replay_failed")
    return process.stdout.decode("utf-8")


def evaluate_once() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="kcmvp-e2e-structural-") as directory:
        root = Path(directory)
        source_path = root / "fixture.c"
        source_path.write_text(FIXTURE, encoding="utf-8")
        captured = capture_trusted_preprocessing(
            source_path=source_path, compiler="clang",
            arguments=["-x", "c", "-std=c11"], cwd=root,
            environment={"LANG": "C"}, allowlisted_environment={"LANG"},
            candidate_id="synthetic-lea001", rule_id="LEA-001",
            runtime_secret=SECRET,
        )
        envelope = captured["envelope"]
        private = captured["private_capture"]
        analyzed = _preprocessed(private)
        expected = dict(envelope["provenance"])
        binding = verify_and_bind_preprocessing(
            envelope=envelope, runtime_secret=SECRET, expected=expected,
            private_capture=private, analyzed_source=analyzed,
        )
        reaching = prove_straightline_output_reaching_defs(
            analyzed, function_name="schedule", output_parameter="out",
            preprocessing_binding=binding,
        )
        lea = prove_lea001_block_semantics(
            analyzed, preprocessing_binding=binding,
        )
        rhs_coverage = prove_lea001_rhs_coverage(
            analyzed, function_name="lea_encrypt_block",
            preprocessing_binding=binding,
        )

        attacks = {
            "analyzed_byte_mutation": verify_and_bind_preprocessing(
                envelope=envelope, runtime_secret=SECRET, expected=expected,
                private_capture=private, analyzed_source=analyzed + " ",
            ) is None,
            "wrong_runtime_secret": verify_and_bind_preprocessing(
                envelope=envelope, runtime_secret=b"z" * 32, expected=expected,
                private_capture=private, analyzed_source=analyzed,
            ) is None,
            "reaching_source_rebinding": "structural_complete" not in
                prove_straightline_output_reaching_defs(
                    analyzed.replace("out[1] = round + 2;", "out[0] = 0;"),
                    function_name="schedule", output_parameter="out",
                    preprocessing_binding=binding,
                ),
            "lea_extent_rebinding": "structural_complete" not in
                prove_lea001_block_semantics(
                    analyzed.replace("i < 16", "i < 15"),
                    preprocessing_binding=binding,
                ),
        }
        definitions = reaching.get("reaching_definitions", [])
        return {
            "preprocessing_binding": binding is not None,
            "reaching_definition_structural_complete":
                reaching.get("structural_complete") is True,
            "lea001_structural_complete": lea.get("structural_complete") is True,
            "lea001_rhs_coverage": {
                "covered": len(rhs_coverage.get("coverage", {}).get("indices", [])),
                "total": 16,
                "structural_complete": rhs_coverage.get("structural_complete") is True,
            },
            "exact_rhs_ast_coverage": {
                "covered": sum(isinstance(row.get("rhs_ast_sha256"), str)
                               and len(row["rhs_ast_sha256"]) == 64
                               for row in definitions),
                "total": len(definitions),
            },
            "mutation_attacks_blocked": attacks,
            "semantic_authorization": 0,
            "api_calls": 0,
        }


def run_benchmark(*, warm_runs: int = 3) -> dict[str, Any]:
    started = time.perf_counter()
    cold = evaluate_once()
    cold_ms = (time.perf_counter() - started) * 1000
    warm_ms: list[float] = []
    warm_results: list[dict[str, Any]] = []
    for _ in range(warm_runs):
        started = time.perf_counter()
        warm_results.append(evaluate_once())
        warm_ms.append((time.perf_counter() - started) * 1000)
    invariant = all(row == cold for row in warm_results)
    return {
        "schema_version": "1.0",
        "benchmark": "sealed-preprocess-clang-lea001-synthetic-e2e",
        "population": {"synthetic_fixtures": 1, "warm_runs": warm_runs},
        "result": cold,
        "repeat_invariant": invariant,
        "latency_ms": {
            "cold": round(cold_ms, 3),
            "warm_mean": round(statistics.mean(warm_ms), 3),
            "warm_median": round(statistics.median(warm_ms), 3),
            "warm_max": round(max(warm_ms), 3),
        },
        "interpretation": "structural_only_semantic_authorization_forbidden",
    }


if __name__ == "__main__":
    print(json.dumps(run_benchmark(), ensure_ascii=False, indent=2, sort_keys=True))
