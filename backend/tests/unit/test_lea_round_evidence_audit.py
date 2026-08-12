import hashlib
import json
from pathlib import Path


BACKEND = Path(__file__).resolve().parents[2]
INDEX = BACKEND / "data" / "evidence" / "official_units.local.json"
ATOMIC = BACKEND / "mapping" / "atomic_claim_evidence_registry.json"

EQUATIONS = {
    "LEA-027": [7, 8, 6],
    "LEA-028": [10, 11, 9],
    "LEA-029": [13, 14, 12],
    "LEA-030": [15],
    "LEA-031": [7, 8, 6, 10, 11, 9, 13, 14, 12],
}
UNIT_TEXT_SHA256 = {
    6: "2ac68d1c79b788c9e80be3ddbdd3d11b0e7a1ae725d122b3931d312fe1f066f5",
    7: "531c77cd66d8e658b9c05197cb1e26d57a1f908091c2adfdf4f026d1488d9188",
    8: "173852e2e2daa18c84b640492bdcfc15180c930c7076543f65f0253d4f26c595",
    9: "277625ccc2189098d9b5fa3e5f2f0bcaf67b36d8b034e2a1e421ba37af83fc8a",
    10: "9d80cb72a7d665184e2104b838dde0ce6da1adb58589dc46b900a417cf7432c8",
    11: "c9c7f0c018da62c6e60d0a00b5fcaaa756f6284daebdd4a4d9bab9c88380fc89",
    12: "1130ad7e3e1e27f127968b891137c5546c4ab044d31fdeefc427a3e14fae82b9",
    13: "0aab8d48a12f98ac3c6072f507fc9034663f5ac233501c8003eef02df6cc35e6",
    14: "d624ee3ceabf8edbe0a99c3c3fba3a5077ce17a7b458abaad0d23b29561c6bbf",
    15: "769755bac55d0faeb71e05acf6632f9e24144425f1ed2d57f742b66162d96f29",
}


def test_normative_units_are_hash_bound_to_the_local_official_index():
    payload = json.loads(INDEX.read_text(encoding="utf-8"))
    source = next(x for x in payload["sources"] if x["source_id"] == "LEA_DATASHEET_KO")
    assert source["sha256"] == "b0c065c527be33984c779b16f9bd26024b92254bf8bf374a13b95d599fb3b795"
    units = {x["unit_id"]: x for x in payload["units"]}
    for blocks in EQUATIONS.values():
        for block in blocks:
            unit = units[f"LEA_DATASHEET_KO:p0013:b{block:03d}"]
            assert unit["authority_tier"] == "standard"
            assert unit["locator"]["page"] == 13
            assert unit["locator"]["section"] == "5.2.1. 암호화 함수"
            assert unit["text_sha256"] == UNIT_TEXT_SHA256[block]
            assert hashlib.sha256(unit["text"].encode()).hexdigest() == UNIT_TEXT_SHA256[block]


def test_index_source_hash_matches_primary_pdf_bytes():
    primary = BACKEND.parent / (
        "RAG_document/RAG_LEA/"
        "LEA표준 규격서_LEA A 128-Bit Block Cipher Datasheets-Korean.pdf"
    )
    assert hashlib.sha256(primary.read_bytes()).hexdigest() == (
        "b0c065c527be33984c779b16f9bd26024b92254bf8bf374a13b95d599fb3b795"
    )


def test_atomic_claims_require_every_fragment_of_each_normative_equation():
    rows = json.loads(ATOMIC.read_text(encoding="utf-8"))["rules"]
    for rule_id, blocks in EQUATIONS.items():
        claim = rows[rule_id][0]
        assert claim["claim_id"] == f"{rule_id}:C1"
        assert claim["allowed_evidence_unit_ids"] == [
            f"LEA_DATASHEET_KO:p0013:b{block:03d}" for block in blocks
        ]
        assert claim["program_fact"]["context_required"] is True


def test_extraction_column_order_is_explicit_and_not_sorted_into_false_equations():
    # PDF geometry places each equation's final RK fragment before the next line's
    # left-hand side in extraction order. Sorting the block numbers would splice
    # different equations together, so the audited semantic order is intentional.
    assert EQUATIONS["LEA-027"] == [7, 8, 6]
    assert EQUATIONS["LEA-028"] == [10, 11, 9]
    assert EQUATIONS["LEA-029"] == [13, 14, 12]


def test_no_partial_equation_is_registered_as_atomic_entailment():
    rows = json.loads(ATOMIC.read_text(encoding="utf-8"))["rules"]
    for rule_id in ("LEA-027", "LEA-028", "LEA-029"):
        assert len(rows[rule_id][0]["allowed_evidence_unit_ids"]) == 3
    assert set(rows["LEA-031"][0]["allowed_evidence_unit_ids"]) == {
        f"LEA_DATASHEET_KO:p0013:b{block:03d}" for block in range(6, 15)
    }
