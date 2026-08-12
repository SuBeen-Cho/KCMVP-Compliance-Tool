"""Build an aggregate-only summary without mixing current and historical cohorts."""
from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build(snapshot: dict[str, Any], *, snapshot_sha256: str,
          router: dict[str, Any], selective: dict[str, Any],
          calibration: dict[str, Any], grounded: dict[str, Any],
          compile_shadow: dict[str, Any]) -> dict[str, Any]:
    sources=snapshot.get("sources");candidates=snapshot.get("candidates")
    if not isinstance(sources,list) or not isinstance(candidates,list) or len(candidates)!=265:
        raise ValueError("current_265_snapshot_required")
    lines=Counter();files=Counter();counts=Counter()
    for row in sources:
        prefix=str(row.get("source_id","")).split("/")[0]
        if prefix not in {f"set-{i}" for i in range(1,8)}:raise ValueError("unknown_set_source")
        lines[prefix]+=int(row.get("lines",0));files[prefix]+=1
    for row in candidates:
        prefix=str(row.get("payload",{}).get("source_id","")).split("/")[0]
        counts[prefix]+=1
    strata=[]
    for number in range(1,8):
        key=f"set-{number}";kind="synthetic_injected" if number<=4 else "commercial_module_case_study"
        strata.append({"set":number,"dataset_kind":kind,"source_files":files[key],"physical_lines":lines[key],
                       "l1_candidates":counts[key],"candidates_per_kloc":round(counts[key]/lines[key]*1000,6)})
    held=calibration["calibration"]["heldout_metrics"]
    pair=calibration["paired_binary"]
    return {
      "schema_version":"1.0","evaluation":"final_proxy_performance_summary",
      "claim_limit":"Current coverage/candidate density and historical same-model proxy metrics are separate cohorts; no human-GT or certified-module accuracy claim.",
      "current_current_head":{"snapshot_sha256":snapshot_sha256,"sets":strata,
        "aggregate":{"source_files":sum(files.values()),"physical_lines":sum(lines.values()),"l1_candidates":265},
        "router":router["stage_distribution"],"authenticated_program_fact_coverage":0.0,
        "synthetic_compile_shadow":compile_shadow["aggregate"]},
      "historical_proxy":{"population":selective["population"],"routing_all":selective["routing_all"],
        "routing_binary_eligible":selective["routing_binary_eligible"],"hold_analysis":selective["hold_analysis"],
        "post_selector_heldout":{"n":held["n"],"precision":held["precision"],"recall":held["recall"],"f1":held["f1"],
          "tp":held["tp"],"fp":held["fp"],"fn":held["fn"],"tn":held["tn"],
          "f1_group_bootstrap_95_ci":calibration["calibration"]["heldout_group_bootstrap_95_ci"]["f1"]},
        "rag_no_rag":{"paired_unique_candidates":pair["paired_n"],"no_rag_only_correct":pair["mcnemar_discordance_counts"]["left_only_correct"],
          "rag_only_correct":pair["mcnemar_discordance_counts"]["right_only_correct"],"mcnemar_exact_p":pair["mcnemar_exact_two_sided_p"]},
        "grounded_verifier":{"population":grounded["population"]["exact_ai_ready"],
          "pass":grounded["conditions"]["grounded"]["verifier_pass_count"],
          "pass_rate":grounded["conditions"]["grounded"]["verifier_pass_count"]/grounded["population"]["exact_ai_ready"],
          "final_abstain":grounded["conditions"]["grounded"]["verified_final_labels"]["abstain"],
          "physical_calls":grounded["execution"]["physical_api_request_count"],
          "input_tokens":grounded["execution"]["physical_input_tokens"],"output_tokens":grounded["execution"]["physical_output_tokens"],
          "estimated_cost_usd":grounded["execution"]["physical_estimated_cost_usd"]}},
      "not_measured":{"four_class_accuracy":None,"macro_f1":None,"current_end_to_end_accuracy":None,
        "certified_module_precision_recall_f1":None,"reason":"No independent human GT and current/proxy candidate identity differs for one occurrence."},
      "api_calls_for_summary":0,"privacy":"aggregate_only"
    }

