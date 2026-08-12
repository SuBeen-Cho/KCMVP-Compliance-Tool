import zipfile

import pytest

from experiments.final_eval_readiness import build, inspect_archives
def inv(n=0):return {"set_count":7,"sets_with_build_manifest":n,"sets":[]}
def test_current_state_blocks_final_metrics():
 r=build(inv(),independent_gt=False,authenticated_fact_coverage=0,citation_entailment=0,clone_disjoint_split=False);assert r["ready_for_final_performance_evaluation"] is False;assert r["decision"]=="continue_priority_development";assert "final_f1" in r["blocked_metrics"]
def test_every_gate_is_required():
 base=dict(inventory=inv(7),independent_gt=True,authenticated_fact_coverage=.95,citation_entailment=.95,clone_disjoint_split=True)
 assert build(**base)["ready_for_final_performance_evaluation"] is True
 for key in ("independent_gt","clone_disjoint_split"):
  value=dict(base);value[key]=False;assert build(**value)["ready_for_final_performance_evaluation"] is False
def test_population_must_be_all_seven_sets():
 with pytest.raises(ValueError,match="seven_set"):build({"set_count":6},independent_gt=True,authenticated_fact_coverage=1,citation_entailment=1,clone_disjoint_split=True)

def test_archive_inventory_distinguishes_source_only_and_build_context(tmp_path):
 paths=[]
 for number in range(1,8):
  path=tmp_path/f"set-{number}.zip"
  with zipfile.ZipFile(path,"w") as archive:
   archive.writestr("src/example.c","int main(void){return 0;}\n")
   if number>=5:archive.writestr("CMakeLists.txt","project(example C)\n")
  paths.append(path)
 inventory=inspect_archives(paths)
 assert inventory["set_count"]==7
 assert inventory["sets_with_build_manifest"]==3
 assert [row["compile_context_reconstructable"] for row in inventory["sets"]]==[False]*4+[True]*3

def test_subdirectory_fragments_and_generated_makefiles_are_not_reconstructable(tmp_path):
 paths=[]
 for number in range(1,8):
  path=tmp_path/f"set-{number}.zip"
  with zipfile.ZipFile(path,"w") as archive:
   archive.writestr("src/example.c","int example(void){return 0;}\n")
   if number>=5:
    archive.writestr("src/CMakeLists.txt","add_library(example example.c)\n")
    archive.writestr("test/Makefile","CMAKE_SOURCE_DIR = /stale/absolute/path\n")
  paths.append(path)
 inventory=inspect_archives(paths)
 assert inventory["sets_with_build_files"]==3
 assert inventory["sets_with_build_manifest"]==0
 assert all(not row["compile_context_reconstructable"] for row in inventory["sets"])
