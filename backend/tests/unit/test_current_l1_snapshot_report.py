import json
from pathlib import Path

from experiments.current_l1_snapshot_report import build
from experiments.l1_snapshot import build_snapshot


def test_report_is_aggregate_and_comparison_does_not_merge(tmp_path: Path):
    root=tmp_path/"src"; root.mkdir(); (root/"a.c").write_text("int x;\n")
    candidate={"file":"a.c","line":1,"rule_id":"R-1","snippet":"secret"}
    provenance={"git_commit":"a"*40,"workspace_sha256":"b"*64,
                "rules_sha256":"c"*64,"prompts_sha256":"d"*64}
    current=build_snapshot(root,[candidate],set_id="new",provenance=provenance)
    old=build_snapshot(root,[candidate,candidate],set_id="old",provenance=provenance)
    report=build(current,current_file_sha256="f"*64,latency_ms=1.2,historical=old)
    encoded=json.dumps(report)
    assert report["strict_validation"]["candidate_count"]==1
    assert report["historical_aggregate_comparison"]["candidate_count_delta"]==-1
    assert report["historical_aggregate_comparison"]["rule_frequency_delta"]=={"R-1":-1}
    assert "secret" not in encoded and "a.c" not in encoded
