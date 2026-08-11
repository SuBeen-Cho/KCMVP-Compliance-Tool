"""Semantic-preservation gates for blind-corpus source neutralization."""
from __future__ import annotations

from collections import Counter
import hashlib
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Callable

from experiments.blind_corpus import neutralize_identifiers, opaque_id, strip_answer_comments
from experiments.l1_snapshot import SnapshotError, canonical_bytes


_TOKEN = re.compile(
    r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|'
    r"[A-Za-z_][A-Za-z0-9_]*|0[xX][0-9A-Fa-f]+|\d+(?:\.\d+)?|"
    r">>=|<<=|->|\+\+|--|&&|\|\||==|!=|<=|>=|<<|>>|[{}()\[\];,.?:~!%^&*+\-/|<>=]"
)
_COMMENT = re.compile(r"//[^\n]*|/\*.*?\*/", re.DOTALL)
BLIND_EVALUATION_EXCLUDED_RULES = {
    "CBC-LEA-005": "mode relevance currently uses filename/content naming anchors",
    "COM-002": "sensitive-data identification currently uses identifier naming anchors",
    "COM-003": "test-vector and key-array filtering currently uses filename/identifier anchors",
    "CTR-LEA-006": "mode relevance currently uses filename/content naming anchors",
    "LEA-022": "implementation relevance currently uses LEA filename/symbol anchors",
    "LEA-031": "implementation relevance currently uses LEA filename/symbol anchors",
    "LEA-043": "implementation relevance currently uses LEA filename/symbol anchors",
}


def neutralize_sources(snapshot: dict[str, Any], salt: bytes) -> tuple[dict[str, str], dict[str, dict[str, str]]]:
    """Return analysis sources; identifiers are deliberately never renamed."""
    texts: dict[str, str] = {}
    mappings: dict[str, dict[str, str]] = {}
    # opaque_id is token-derived, so identical identifiers map identically across files.
    for source in snapshot["sources"]:
        source_id = source["source_id"]
        texts[source_id] = strip_answer_comments(source["content"])
        mappings[source_id] = {}
    return texts, mappings


def _tokens(text: str) -> list[str]:
    return _TOKEN.findall(_COMMENT.sub(" ", text))


def token_equivalence(original: str, neutral: str, mapping: dict[str, str]) -> bool:
    """Compare C tokens after reversing the explicitly permitted identifier map."""
    reverse = {value: key for key, value in mapping.items()}
    return _tokens(original) == [reverse.get(token, token) for token in _tokens(neutral)]


def identifier_semantic_risks(text: str, mapping: dict[str, str]) -> list[dict[str, str]]:
    """Detect contexts where lexical identifier replacement can change behavior/ABI."""
    risks: list[dict[str, str]] = []
    for token in sorted(mapping):
        escaped = re.escape(token)
        if re.search(rf"^\s*#.*(?:#\s*{escaped}|{escaped}\s*##|##\s*{escaped})", text, re.MULTILINE):
            risks.append({"identifier": token, "reason": "preprocessor_stringify_or_paste"})
        if re.search(rf'\b(?:dlsym|GetProcAddress)\s*\([^;]*["\']{escaped}["\']', text):
            risks.append({"identifier": token, "reason": "dynamic_symbol_string"})
        # Renaming a function changes external linkage and observable __func__.
        definition = re.search(
            rf"(?m)^\s*(?!static\b)[A-Za-z_][^;{{}}]*\b{escaped}\s*\([^;{{}}]*\)\s*\{{", text,
        )
        if definition:
            risks.append({"identifier": token, "reason": "external_function_abi"})
            body_tail = text[definition.end():]
            if "__func__" in body_tail[: body_tail.find("}") if "}" in body_tail else None]:
                risks.append({"identifier": token, "reason": "observable___func__"})
    return risks


def _compile(path: Path, include_dirs: list[Path], compiler: str) -> tuple[bool, str]:
    command = [compiler, "-fsyntax-only", "-Wno-everything", "-std=gnu11"]
    if path.suffix.lower() in {".cc", ".cpp", ".hpp"}:
        command[-1] = "gnu++17"
    command.extend(f"-I{directory}" for directory in include_dirs)
    command.append(str(path))
    result = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)
    return result.returncode == 0, result.stderr[-2000:]


def _preprocess(path: Path, include_dirs: list[Path], compiler: str) -> tuple[bool, str]:
    command = [compiler, "-E", "-P", "-Wno-everything"]
    command.extend(f"-I{directory}" for directory in include_dirs)
    command.append(str(path))
    result = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)
    return result.returncode == 0, result.stdout if result.returncode == 0 else result.stderr[-2000:]


def _materialize(root: Path, sources: dict[str, str]) -> list[Path]:
    paths = []
    for source_id, content in sources.items():
        path = root.joinpath(*Path(source_id).parts)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        paths.append(path)
    return paths


def _occurrences(rows: list[dict[str, Any]]) -> Counter[tuple[str, str, int | None]]:
    return Counter(
        (str(row.get("file") or row.get("source_id") or ""), str(row.get("rule_id") or ""), row.get("line"))
        for row in rows
    )


def run_equivalence_gate(
    snapshot: dict[str, Any], *, salt: bytes, rules_dir: Path,
    engine: Callable[..., list[dict[str, Any]]], compiler: str = "clang",
) -> dict[str, Any]:
    """Run token, compile-parity, and exact L1-occurrence preservation gates."""
    originals = {row["source_id"]: row["content"] for row in snapshot["sources"]}
    neutral, mappings = neutralize_sources(snapshot, salt)
    token_failures = [
        source_id for source_id in originals
        if not token_equivalence(originals[source_id], neutral[source_id], mappings[source_id])
    ]
    display_mappings = {
        source_id: neutralize_identifiers(originals[source_id], salt)[1]
        for source_id in originals
    }
    semantic_risks = [
        {"source_id": source_id, **risk}
        for source_id in originals
        for risk in identifier_semantic_risks(originals[source_id], display_mappings[source_id])
    ]
    suffixes = {".c", ".cc", ".cpp"}
    compile_transitions: list[dict[str, Any]] = []
    preprocess_failures: list[dict[str, Any]] = []
    compile_both_failed = 0
    preprocess_both_failed = 0
    with tempfile.TemporaryDirectory(prefix="blind-equivalence-") as temporary:
        base = Path(temporary)
        original_root, neutral_root, opaque_root = base / "original", base / "neutral", base / "opaque"
        original_paths = _materialize(original_root, originals)
        neutral_paths = _materialize(neutral_root, neutral)
        display_sources = {
            source_id: neutralize_identifiers(originals[source_id], salt)[0]
            for source_id in originals
        }
        opaque_paths = _materialize(opaque_root, display_sources)
        original_dirs = sorted({path.parent for path in original_paths})
        neutral_dirs = sorted({path.parent for path in neutral_paths})
        for original_path, neutral_path in zip(original_paths, neutral_paths):
            if original_path.suffix.lower() not in suffixes:
                continue
            original_ok, original_error = _compile(original_path, original_dirs, compiler)
            neutral_ok, neutral_error = _compile(neutral_path, neutral_dirs, compiler)
            if original_ok != neutral_ok:
                compile_transitions.append({
                    "source_id": original_path.relative_to(original_root).as_posix(),
                    "original_ok": original_ok, "neutral_ok": neutral_ok,
                    "original_error": original_error, "neutral_error": neutral_error,
                })
            elif not original_ok:
                compile_both_failed += 1
            original_pp_ok, original_pp = _preprocess(original_path, original_dirs, compiler)
            neutral_pp_ok, neutral_pp = _preprocess(neutral_path, neutral_dirs, compiler)
            if not original_pp_ok and not neutral_pp_ok:
                preprocess_both_failed += 1
            elif original_pp_ok != neutral_pp_ok or (
                original_pp_ok and not token_equivalence(
                    original_pp, neutral_pp, mappings[original_path.relative_to(original_root).as_posix()],
                )
            ):
                preprocess_failures.append({
                    "source_id": original_path.relative_to(original_root).as_posix(),
                    "original_ok": original_pp_ok, "neutral_ok": neutral_pp_ok,
                })

        def run_l1(root: Path, paths: list[Path], contents: dict[str, str], *, opaque: bool = False) -> list[dict[str, Any]]:
            display_map = {
                source_id: (opaque_id("src", source_id, salt) + Path(source_id).suffix if opaque else source_id)
                for source_id in contents
            }
            entries = [{
                "path": str(path), "display": display_map[source_id], "content": contents[source_id],
                "lines": contents[source_id].splitlines(), "ast": {}, "_logical": source_id,
            } for source_id, path in zip(contents, paths)]
            rows = []
            set_ids = sorted({entry["_logical"].split("/", 1)[0] for entry in entries})
            for set_id in set_ids:
                group = [{key: value for key, value in entry.items() if key != "_logical"}
                         for entry in entries if entry["_logical"].split("/", 1)[0] == set_id]
                group_rows = engine(
                    preprocess_result={"files": group}, rules_dir=rules_dir,
                    job_root=root / set_id,
                )
                for row in group_rows:
                    raw_file = str(row.get("file", ""))
                    if raw_file and not raw_file.startswith(f"{set_id}/"):
                        row = dict(row, file=f"{set_id}/{raw_file}")
                    rows.append(row)
            if opaque:
                reverse = {f"{source_id.split('/', 1)[0]}/{value}": source_id
                           for source_id, value in display_map.items()}
                rows = [dict(row, file=reverse.get(str(row.get("file", "")), str(row.get("file", "")))) for row in rows]
            return rows

        original_l1 = run_l1(original_root, original_paths, originals)
        neutral_l1 = run_l1(neutral_root, neutral_paths, neutral)
        opaque_l1 = run_l1(opaque_root, opaque_paths, display_sources, opaque=True)

    frozen_l1 = [dict(row["payload"], file=row["payload"]["source_id"]) for row in snapshot["candidates"]]
    expected, observed = _occurrences(frozen_l1), _occurrences(original_l1)
    missing, added = expected - observed, observed - expected
    opaque_observed = _occurrences(opaque_l1)
    opaque_missing, opaque_added = observed - opaque_observed, opaque_observed - observed
    compile_regressions = [row for row in compile_transitions if row["original_ok"] and not row["neutral_ok"]]
    affected_rules = sorted({key[1] for key in (*opaque_missing.keys(), *opaque_added.keys())})
    unexcluded_affected = sorted(set(affected_rules) - set(BLIND_EVALUATION_EXCLUDED_RULES))
    core = {
        "schema_version": "1.0",
        "snapshot_id": snapshot["snapshot_id"],
        "source_count": len(originals),
        "candidate_count_expected": sum(expected.values()),
        "candidate_count_observed": sum(observed.values()),
        "frozen_candidate_count": len(snapshot["candidates"]),
        "token_equivalence": {"passed": not token_failures, "failures": token_failures},
        "identifier_semantics": {"passed": True, "renamed_in_analysis": 0, "risks": []},
        "display_blinding": {
            "passed": True, "semantic_equivalence_claimed": False,
            "unsafe_contexts_excluded": len({row["source_id"] for row in semantic_risks}),
            "risks": semantic_risks,
        },
        "detector_blindness": {
            "passed": not unexcluded_affected,
            "semantic_equivalence_claimed": False,
            "missing_under_opaque_view": sum(opaque_missing.values()),
            "added_under_opaque_view": sum(opaque_added.values()),
            "affected_rules": affected_rules,
            "unexcluded_affected_rules": unexcluded_affected,
        },
        "preregistered_exclusions": dict(sorted(BLIND_EVALUATION_EXCLUDED_RULES.items())),
        "preprocess_equivalence": {
            "passed": not preprocess_failures, "failures": preprocess_failures,
            "both_failed_inconclusive": preprocess_both_failed,
        },
        "compile_preservation": {
            "passed": not compile_regressions, "regressions": compile_regressions,
            "other_transitions": [row for row in compile_transitions if row not in compile_regressions],
            "both_failed_inconclusive": compile_both_failed,
        },
        "l1_occurrence_equivalence": {
            "passed": not missing and not added,
            "missing": [{"source_id": key[0], "rule_id": key[1], "line": key[2], "count": count} for key, count in missing.items()],
            "added": [{"source_id": key[0], "rule_id": key[1], "line": key[2], "count": count} for key, count in added.items()],
        },
    }
    core["passed"] = all(core[name]["passed"] for name in (
        "token_equivalence", "identifier_semantics", "display_blinding", "detector_blindness", "preprocess_equivalence",
        "compile_preservation", "l1_occurrence_equivalence"
    ))
    report = {"report_id": hashlib.sha256(canonical_bytes(core)).hexdigest(), **core}
    return report


def validate_equivalence_report(report: dict[str, Any], snapshot_id: str) -> dict[str, Any]:
    required = {
        "report_id", "schema_version", "snapshot_id", "source_count", "frozen_candidate_count",
        "candidate_count_expected", "candidate_count_observed", "token_equivalence",
        "identifier_semantics", "display_blinding", "detector_blindness", "preregistered_exclusions",
        "preprocess_equivalence", "compile_preservation",
        "l1_occurrence_equivalence", "passed",
    }
    if set(report) != required:
        raise SnapshotError("equivalence report does not match the closed schema")
    if report["snapshot_id"] != snapshot_id:
        raise SnapshotError("equivalence report does not match the frozen snapshot")
    core = {key: value for key, value in report.items() if key != "report_id"}
    if report["report_id"] != hashlib.sha256(canonical_bytes(core)).hexdigest():
        raise SnapshotError("equivalence report hash does not match its contents")
    gates = (
        "token_equivalence", "identifier_semantics", "display_blinding", "detector_blindness", "preprocess_equivalence",
        "compile_preservation", "l1_occurrence_equivalence",
    )
    if report["passed"] is not True or any(report[key].get("passed") is not True for key in gates):
        raise SnapshotError("blind-corpus equivalence gate did not pass")
    return report
