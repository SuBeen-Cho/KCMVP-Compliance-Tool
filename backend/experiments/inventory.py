"""Build a deterministic inventory of YAML rules used by an experiment."""
from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any

import yaml


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_rule_inventory(rules_dir: Path) -> dict[str, Any]:
    rules: list[dict[str, Any]] = []
    files = []
    domains = Counter()
    for path in sorted(rules_dir.rglob("*.yaml")):
        payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        entries = payload.get("rules", []) if isinstance(payload, dict) else payload
        if not isinstance(entries, list):
            raise ValueError(f"rules must be a list: {path}")
        files.append({"path": str(path.relative_to(rules_dir)), "sha256": sha256_file(path)})
        domains[path.relative_to(rules_dir).parts[0]] += len(entries)
        for entry in entries:
            if not isinstance(entry, dict) or not entry.get("id"):
                raise ValueError(f"invalid rule entry: {path}")
            rules.append(entry)
    ids = [str(rule["id"]) for rule in rules]
    duplicates = sorted(rule_id for rule_id, count in Counter(ids).items() if count > 1)
    return {
        "schema_version": "1.0",
        "total_rules": len(rules),
        "unique_rule_ids": len(set(ids)),
        "duplicate_rule_ids": duplicates,
        "by_domain": dict(sorted(domains.items())),
        "by_category": dict(sorted(Counter(str(rule.get("category", "unspecified")) for rule in rules).items())),
        "by_pattern_type": dict(sorted(Counter(str(rule.get("pattern_type", "unspecified")) for rule in rules).items())),
        "files": files,
    }


def main() -> None:
    backend = Path(__file__).resolve().parents[1]
    print(json.dumps(build_rule_inventory(backend / "rules"), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
