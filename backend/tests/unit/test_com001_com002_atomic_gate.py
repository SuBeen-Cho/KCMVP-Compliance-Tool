import json
from pathlib import Path
def gate():return json.loads((Path(__file__).resolve().parents[2]/"mapping/com001_com002_atomic_gate.json").read_text())
def test_com001_zeroization_duty_is_separate_from_function_name_allowlist():
 r=gate()["rules"]["COM-001"];assert r["decision"]=="remain_fail_closed";assert any("after use" in x for x in r["directly_entailed"]);assert any("function names" in x for x in r["not_directly_entailed"])
def test_com002_void_set_key_and_negative_mode_returns_are_not_conflated():
 r=gate()["rules"]["COM-002"];assert any("void" in x for x in r["directly_entailed"]);assert any("same return signature" in x for x in r["not_directly_entailed"]);assert r["decision"]=="remain_fail_closed"
def test_no_production_authorization_from_atomic_text_only():assert gate()["production_authorized"] is False
