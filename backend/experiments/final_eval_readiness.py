"""Fail-closed final-evaluation readiness gate."""
from __future__ import annotations
import hashlib,json,zipfile
from pathlib import Path,PurePosixPath
from typing import Any
from experiments.workspace_guard import guarded_output_path

BUILD_NAMES={"compile_commands.json","makefile","cmakelists.txt","meson.build","build.ninja"}
def sha(b:bytes)->str:return hashlib.sha256(b).hexdigest()
def inspect_archives(paths:list[Path])->dict[str,Any]:
 rows=[]
 for number,path in enumerate(paths,1):
  with zipfile.ZipFile(path) as z:
   names=[PurePosixPath(x.filename) for x in z.infolist() if not x.is_dir()]
  build=[str(x) for x in names if x.name.lower() in BUILD_NAMES]
  source=sum(x.suffix.lower() in {".c",".h",".cc",".cpp",".hpp"} for x in names)
  rows.append({"set":number,"archive_sha256":sha(path.read_bytes()),"source_files":source,
               "build_manifest_files":len(build),"compile_context_reconstructable":bool(build)})
 return {"sets":rows,"set_count":len(rows),"sets_with_build_manifest":sum(x["compile_context_reconstructable"] for x in rows)}
def build(inventory:dict[str,Any],*,independent_gt:bool,authenticated_fact_coverage:float,
          citation_entailment:float,clone_disjoint_split:bool)->dict[str,Any]:
 if inventory.get("set_count")!=7:raise ValueError("seven_set_inventory_required")
 gates={"all_sets_have_build_manifest":inventory["sets_with_build_manifest"]==7,
        "independent_human_gt":independent_gt,"authenticated_program_fact_coverage_ge_0_95":authenticated_fact_coverage>=.95,
        "citation_entailment_ge_0_95":citation_entailment>=.95,"clone_disjoint_split_frozen":clone_disjoint_split}
 ready=all(gates.values())
 return {"schema_version":"1.0","evaluation":"final_performance_readiness_gate",
         "ready_for_final_performance_evaluation":ready,"gates":gates,"inventory":inventory,
         "observed":{"authenticated_program_fact_coverage":authenticated_fact_coverage,"citation_entailment":citation_entailment},
         "decision":"run_final_evaluation" if ready else "continue_priority_development",
         "blocked_metrics":[] if ready else ["final_accuracy","final_precision","final_recall","final_f1","confirmatory_mcnemar"],
         "claim_limit":"Readiness only; it is not a performance result."}
def main():
 import argparse
 p=argparse.ArgumentParser();p.add_argument("archives",nargs=7,type=Path);p.add_argument("--output",required=True,type=Path);a=p.parse_args()
 value=build(inspect_archives(a.archives),independent_gt=False,authenticated_fact_coverage=0.0,citation_entailment=0.0,clone_disjoint_split=False)
 guarded_output_path(a.output).write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
if __name__=="__main__":main()
