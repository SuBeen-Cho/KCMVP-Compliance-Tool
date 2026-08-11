"""Opt-in deterministic fact extractor for L3 advisory research."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

_ROOT_KEYS = {"schema_version", "collection", "default_enforcement", "advisories"}
_ADVISORY_KEYS = {"advisory_id", "title", "normative_level", "evidence_unit_ids", "required_features", "allowed_outcomes", "implementation_status"}


def load_specs(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if set(data) != _ROOT_KEYS or data.get("schema_version") != "1.0" or data.get("collection") != "l3_advisory":
        raise ValueError("invalid or open l3_advisory root schema")
    if data.get("default_enforcement") != "disabled" or not isinstance(data.get("advisories"), list):
        raise ValueError("advisories must be disabled by default")
    seen: set[str] = set()
    for row in data["advisories"]:
        if not isinstance(row, dict) or set(row) != _ADVISORY_KEYS:
            raise ValueError("invalid or open advisory schema")
        if row["advisory_id"] in seen or row["allowed_outcomes"] != ["satisfied", "unsafe_observed", "unknown"]:
            raise ValueError("duplicate advisory or invalid outcomes")
        seen.add(row["advisory_id"])
        if not row["evidence_unit_ids"] or not row["required_features"]:
            raise ValueError("advisory evidence and prerequisites are required")
    return data


def _mask_comments_and_strings(source: str) -> str:
    pattern = re.compile(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', re.S)
    return pattern.sub(lambda m: "".join("\n" if c == "\n" else " " for c in m.group()), source)


def extract_pad002_facts(source: str) -> dict[str, Any]:
    """Extract observable same-function event ordering; never infer callees."""
    masked = _mask_comments_and_strings(source)
    patterns = {
        "decrypt_event": r"(?i)\b(?:cbc_)?decrypt\w*\s*\(",
        "padding_validation_event": r"(?i)\b(?:validate|verify|check)_(?:pkcs\d*_|iso\w*_)?padding\s*\(",
        "padding_removal_event": r"(?i)\b(?:remove|strip|unpad)_(?:pkcs\d*_|iso\w*_)?padding\s*\(",
        "plaintext_release_event": r"(?i)\b(?:return_plaintext|release_plaintext|send_plaintext|copy_plaintext)\s*\(",
    }
    positions = {name: [m.start() for m in re.finditer(regex, masked)] for name, regex in patterns.items()}
    observed = {name: bool(values) for name, values in positions.items()}
    if not observed["decrypt_event"]:
        outcome, reason = "unknown", "decrypt_event_absent_or_interprocedural"
    elif not (observed["padding_removal_event"] or observed["plaintext_release_event"]):
        outcome, reason = "unknown", "no_observable_removal_or_release"
    elif not observed["padding_validation_event"]:
        outcome, reason = "unsafe_observed", "removal_or_release_without_observable_validation"
    else:
        validation = positions["padding_validation_event"][0]
        sink = min(positions["padding_removal_event"] + positions["plaintext_release_event"])
        if validation < sink:
            outcome, reason = "satisfied", "validation_precedes_removal_or_release"
        else:
            outcome, reason = "unsafe_observed", "removal_or_release_precedes_validation"
    return {"advisory_id": "PAD-002", "outcome": outcome, "reason": reason, "facts": observed, "enforcement": "none"}


def run(path: Path, *, enabled: bool) -> dict[str, Any]:
    if not enabled:
        return {"schema_version": "1.0", "enabled": False, "findings": [], "gate": "no_fp_default"}
    source = path.read_text(encoding="utf-8")
    return {"schema_version": "1.0", "enabled": True, "findings": [extract_pad002_facts(source)], "gate": "advisory_only"}


def main() -> int:
    backend = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("--spec", type=Path, default=backend / "rag/l3_advisory_specs.json")
    parser.add_argument("--enable-experimental", action="store_true")
    args = parser.parse_args()
    load_specs(args.spec)
    print(json.dumps(run(args.source, enabled=args.enable_experimental), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
