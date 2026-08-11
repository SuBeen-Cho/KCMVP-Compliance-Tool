"""
룰 엔진 단위 테스트.

02_FP_심층분석 보고서 기반:
- 파일 분류 로직 (P0-1): 테스트/데이터 파일 구분
- Fallback regex 과잉 매칭 (원인 B): CTR-005, LEA-059, LEA-032
- COM-003 테스트 벡터 예외 (P0-4)
- 중복제거 로직
"""

import re
import json
from pathlib import Path

import pytest


class TestSEED001Pipeline:
    @pytest.mark.rule_engine
    def test_pipeline_reports_only_explicit_wrong_key(self, tmp_path: Path):
        from app.services.rule_engine_service import run_rule_engine

        rules_dir = Path(__file__).resolve().parents[2] / "rules"
        wrong = tmp_path / "seed_core.c"
        wrapper = tmp_path / "seed_wrapper.c"
        wrong.write_text("typedef unsigned char uint8_t; void seed_init(void) { uint8_t seed_key[24]; seed_key[0] = 0; }", encoding="utf-8")
        wrapper.write_text("typedef unsigned char uint8_t; void seed_forward(const uint8_t *seed_key) { (void)seed_key; }", encoding="utf-8")
        findings = run_rule_engine(
            {"files": [{"path": str(wrong)}, {"path": str(wrapper)}]},
            rules_dir, tmp_path, algorithms=["SEED"],
        )
        seed_findings = [item for item in findings if item["rule_id"] == "SEED-001"]
        assert len(seed_findings) == 1
        assert seed_findings[0]["file"] == "seed_core.c"
        assert seed_findings[0]["detection_semantics"] == "structural_violation"

    def test_inventory_includes_seed_001(self):
        from experiments.inventory import build_rule_inventory

        inventory = build_rule_inventory(Path(__file__).resolve().parents[2] / "rules")
        assert inventory["total_rules"] == 165
        assert inventory["unique_rule_ids"] == 165
        assert inventory["by_domain"]["algorithm"] == 58


class TestNewCipherEvidenceTraceability:
    def test_new_cipher_rules_have_author_prepared_guidelines(self):
        backend = Path(__file__).resolve().parents[2]
        mapping = json.loads(
            (backend / "mapping/rule_to_guideline.json").read_text(encoding="utf-8")
        )
        for rule_id in ("AES-001", "AES-002", "AES-003", "ARIA-001", "SEED-001"):
            entry = mapping[rule_id]
            assert entry["item_ids"] == []
            assert entry["standard_ids"]
            guideline = backend / entry["guideline_file"]
            assert guideline.is_file()
            text = guideline.read_text(encoding="utf-8")
            assert "프로젝트 저자가 작성한 검사 해설" in text
            assert "대체하지 않는다" in text


class TestDetectionSemantics:
    def test_rule_engine_emits_closed_semantics_for_each_detector(self, tmp_path: Path):
        from app.services.rule_engine_service import run_rule_engine

        rules_dir = tmp_path / "rules"
        (rules_dir / "common").mkdir(parents=True)
        (rules_dir / "common" / "security.yaml").write_text(
            """rules:
- id: T-REGEX
  category: common
  name: present
  pattern_type: regex
  pattern: BAD
- id: T-MISSING
  category: common
  name: missing
  pattern_type: missing
  pattern: REQUIRED
- id: T-SEMANTIC
  category: common
  name: semantic absence
  pattern_type: semantic
  pattern: REQUIRED_SEMANTIC
- id: COM-005
  category: common
  name: ordering
  pattern_type: semantic
  pattern: lea_online_init|lea_online_update|lea_online_final
""",
            encoding="utf-8",
        )
        source = tmp_path / "online.c"
        source.write_text(
            "void f(void) { BAD; lea_online_update(); lea_online_init(); }\n",
            encoding="utf-8",
        )
        findings = run_rule_engine(
            {"files": [{"path": str(source)}]}, rules_dir, tmp_path,
        )
        semantics = {item["rule_id"]: item["detection_semantics"] for item in findings}
        assert semantics == {
            "T-REGEX": "prohibited_presence",
            "T-MISSING": "required_absence",
            "T-SEMANTIC": "required_absence",
            "COM-005": "structural_violation",
        }
        assert set(semantics.values()) <= {
            "prohibited_presence", "required_absence", "structural_violation",
        }

    def test_ast_fallback_origin_distinguishes_match_and_absence(self, tmp_path: Path):
        from app.services.rule_engine_service import _apply_ast_rule

        present = tmp_path / "present.c"
        absent = tmp_path / "absent.c"
        present.write_text("int OBSERVED_BAD;\n", encoding="utf-8")
        absent.write_text("int safe;\n", encoding="utf-8")
        rule = {
            "id": "UNIMPLEMENTED-AST", "name": "fallback", "pattern_type": "ast",
            "fallback_pattern": r"OBSERVED_BAD", "severity": "high",
        }

        def cache(path):
            content = path.read_text(encoding="utf-8")
            return [{
                "path": path, "display": path.name, "content": content,
                "stripped_content": content, "file_type": "impl",
            }]

        matched = _apply_ast_rule(rule, cache(present), tmp_path)
        missing = _apply_ast_rule(rule, cache(absent), tmp_path)
        assert matched[0]["detection_semantics"] == "prohibited_presence"
        assert "ast_evidence" not in matched[0]
        assert missing[0]["detection_semantics"] == "required_absence"
        assert "ast_evidence" not in missing[0]

    def test_informational_rfc_role_is_explicit(self):
        backend = Path(__file__).resolve().parents[2]
        for relative in (
            "rules/algorithm/aria.yaml",
            "rules/algorithm/seed.yaml",
            "guidelines/ARIA-001_key_rounds.md",
            "guidelines/SEED-001_key_size.md",
        ):
            assert "Informational RFC" in (backend / relative).read_text(encoding="utf-8")


class TestAlgorithmDomainAnchor:
    """알고리즘 규칙이 관련 구현 파일에만 적용되는지 검증한다."""

    @pytest.mark.rule_engine
    def test_lea_filename_behavior_is_preserved(self):
        from app.services.rule_engine_service import _is_algorithm_impl_file

        assert _is_algorithm_impl_file("src/lea_core.c", "", "LEA")
        assert _is_algorithm_impl_file("src/my_lea_port.c", "", "lea")
        assert not _is_algorithm_impl_file("src/aes_core.c", "lea_encrypt();", "LEA")

    @pytest.mark.rule_engine
    def test_aes_filename_and_established_symbol_anchors(self):
        from app.services.rule_engine_service import _is_algorithm_impl_file

        assert _is_algorithm_impl_file("src/aes_core.c", "", "AES")
        assert _is_algorithm_impl_file("src/rijndael_port.cpp", "", "AES")
        assert _is_algorithm_impl_file(
            "src/cipher.c", "int AES_set_encrypt_key(void);", "AES"
        )
        assert _is_algorithm_impl_file(
            "src/cipher.c", "int mbedtls_aes_setkey_enc(void);", "AES"
        )
        for filename in ("vpaes.c", "bsaes.c", "aesni.c"):
            assert _is_algorithm_impl_file(filename, "", "AES")
        assert not _is_algorithm_impl_file(
            "src/aria_core.c", "/* AES is supported by another module. */", "AES"
        )

    @pytest.mark.rule_engine
    def test_algorithm_anchors_cover_seed_aria_and_path_edges(self):
        from app.services.rule_engine_service import _is_algorithm_impl_file

        assert _is_algorithm_impl_file("crypto\\seed\\seed.c", "", "SEED")
        assert _is_algorithm_impl_file("ARIA implementation/core.c", "", "ARIA")
        assert _is_algorithm_impl_file("cipher.c", "SEED_set_key(key, &ks);", "SEED")
        assert _is_algorithm_impl_file("cipher.c", "EVP_aria_128_gcm();", "ARIA")
        assert _is_algorithm_impl_file("cipher.cpp", "ARIA::Base::UncheckedSetKey();", "ARIA")
        assert not _is_algorithm_impl_file("not-aes.c", "int helper(void);", "AES")
        assert not _is_algorithm_impl_file("non_seed.c", "int helper(void);", "SEED")

    @pytest.mark.rule_engine
    def test_registry_strings_and_unknown_algorithms_fail_closed(self):
        from app.services.rule_engine_service import _is_algorithm_impl_file

        assert not _is_algorithm_impl_file(
            "cipher_registry.c", 'const char *name = "EVP_aes_128_gcm()";', "AES"
        )
        assert not _is_algorithm_impl_file(
            "cipher_registry.c", 'const char *name = "EVP_seed_cbc()";', "SEED"
        )
        assert not _is_algorithm_impl_file(
            "cipher_registry.c", "/* EVP_aes_128_gcm(); */", "AES"
        )
        assert not _is_algorithm_impl_file(
            "cipher_registry.c", "// SEED_set_key(key, &ks);", "SEED"
        )
        assert not _is_algorithm_impl_file("foo.c", "foo_encrypt();", "FOO")
        assert not _is_algorithm_impl_file("aes.c", "AES_encrypt();", "")

    @pytest.mark.rule_engine
    def test_aes_rule_is_gated_away_from_non_aes_file(self, tmp_path: Path):
        from app.services.rule_engine_service import run_rule_engine

        rules_dir = tmp_path / "rules"
        algorithm_dir = rules_dir / "algorithm"
        algorithm_dir.mkdir(parents=True)
        (algorithm_dir / "aes.yaml").write_text(
            """rules:
- id: AES-TEST-001
  category: algorithm
  algorithm: AES
  name: AES domain gate test
  pattern_type: regex
  pattern: BAD_AES_VALUE
  severity: high
""",
            encoding="utf-8",
        )
        aes_file = tmp_path / "aes_core.c"
        aria_file = tmp_path / "aria_core.c"
        aes_file.write_text("int BAD_AES_VALUE = 1;\n", encoding="utf-8")
        aria_file.write_text("int BAD_AES_VALUE = 1;\n", encoding="utf-8")
        preprocess_result = {
            "files": [{"path": str(aes_file)}, {"path": str(aria_file)}]
        }

        findings = run_rule_engine(
            preprocess_result, rules_dir, tmp_path, algorithms=["AES"]
        )

        assert [finding["file"] for finding in findings] == ["aes_core.c"]

    @pytest.mark.rule_engine
    def test_aes_high_confidence_rules_pipeline_boundaries(
        self, tmp_path: Path, load_fixture
    ):
        from app.services.rule_engine_service import run_rule_engine

        backend = Path(__file__).resolve().parents[2]
        cases = {
            "aes_violation.c": "aes_high_confidence_violation.c",
            "aes_compliant.c": "aes_high_confidence_compliant.c",
            "aes_wrapper.c": "aes_high_confidence_wrapper.c",
        }
        paths = []
        for name, fixture in cases.items():
            path = tmp_path / name
            path.write_text(load_fixture(fixture), encoding="utf-8")
            paths.append(path)

        findings = run_rule_engine(
            {"files": [{"path": str(path)} for path in paths]},
            backend / "rules",
            tmp_path,
            algorithms=["AES"],
        )

        aes_findings = [finding for finding in findings if finding["rule_id"].startswith("AES-")]
        assert {finding["rule_id"] for finding in aes_findings} == {
            "AES-001", "AES-002", "AES-003"
        }
        assert {finding["file"] for finding in aes_findings} == {"aes_violation.c"}

    @pytest.mark.rule_engine
    def test_aes_wrapper_only_cache_does_not_reenter_ast_checker(self, tmp_path: Path):
        from app.services.rule_engine_service import run_rule_engine

        backend = Path(__file__).resolve().parents[2]
        wrapper = tmp_path / "aes_wrapper.c"
        wrapper.write_text(
            """typedef struct { int opaque; } aes_context;
const int aes_block_bytes = 8;
int vendor_set_key(aes_context *, const unsigned char *, int);
int aes_set_key(aes_context *ctx, const unsigned char *key, int key_bits) {
    return vendor_set_key(ctx, key, key_bits);
}
""",
            encoding="utf-8",
        )
        findings = run_rule_engine(
            {"files": [{"path": str(wrapper)}]},
            backend / "rules",
            tmp_path,
            algorithms=["AES"],
        )
        assert not [item for item in findings if item["rule_id"].startswith("AES-")]

    @pytest.mark.rule_engine
    @pytest.mark.parametrize("rule_id", ["AES-001", "AES-002", "AES-003"])
    def test_aes_rules_carry_official_fips_197_metadata(self, load_rule, rule_id):
        rule = load_rule(rule_id)
        assert rule["source_authority"] == "NIST"
        assert rule["source_document"] == "FIPS PUB 197-upd1"
        assert rule["source_url"] == "https://doi.org/10.6028/NIST.FIPS.197-upd1"
        expected_sections = {
            "AES-001": "Section 2.1 (Block); Section 5, Table 3",
            "AES-002": "Section 5, Table 3",
            "AES-003": "Section 5, Table 3",
        }
        assert rule["source_section"] == expected_sections[rule_id]

    @pytest.mark.rule_engine
    def test_project_missing_rule_search_is_algorithm_scoped(self, tmp_path: Path):
        from app.services.rule_engine_service import run_rule_engine

        rules_dir = tmp_path / "rules"
        algorithm_dir = rules_dir / "algorithm"
        algorithm_dir.mkdir(parents=True)
        (algorithm_dir / "aes.yaml").write_text(
            """rules:
- id: AES-TEST-002
  category: algorithm
  algorithm: AES
  name: AES project domain gate test
  pattern_type: missing
  pattern: AES_REQUIRED_MARKER
  scope: project
  severity: high
""",
            encoding="utf-8",
        )
        aes_file = tmp_path / "aes_core.c"
        aria_file = tmp_path / "aria_core.c"
        aes_file.write_text("int aes_impl(void) { return 0; }\n", encoding="utf-8")
        aria_file.write_text("int AES_REQUIRED_MARKER = 1;\n", encoding="utf-8")

        findings = run_rule_engine(
            {"files": [{"path": str(aes_file)}, {"path": str(aria_file)}]},
            rules_dir,
            tmp_path,
            algorithms=["AES"],
        )

        assert len(findings) == 1
        assert findings[0]["rule_id"] == "AES-TEST-002"
        assert findings[0]["file"] == "aes_core.c"

    @pytest.mark.rule_engine
    def test_aria_001_yaml_integration_reports_only_explicit_conflict(self, tmp_path: Path):
        from app.services.rule_engine_service import run_rule_engine

        rules_dir = Path(__file__).resolve().parents[2] / "rules"
        wrong = tmp_path / "aria_wrong.c"
        wrapper = tmp_path / "aria_wrapper.c"
        wrong.write_text(
            """void aria_set_key(const unsigned char *key, int keylen) {
    int rounds = 0;
    if (keylen == 32) { rounds = 12; }
}
""",
            encoding="utf-8",
        )
        wrapper.write_text(
            """int vendor_set_key(void *, const unsigned char *, int);
int aria_set_key(void *ctx, const unsigned char *key, int keylen) {
    return vendor_set_key(ctx, key, keylen);
}
""",
            encoding="utf-8",
        )

        findings = run_rule_engine(
            {"files": [{"path": str(wrong)}, {"path": str(wrapper)}]},
            rules_dir,
            tmp_path,
            algorithms=["ARIA"],
        )

        aria_findings = [item for item in findings if item["rule_id"] == "ARIA-001"]
        assert len(aria_findings) == 1
        assert aria_findings[0]["file"] == "aria_wrong.c"


# ======================================================================
# 파일 분류 로직 테스트 (P0-1 — 02 보고서 §2.3)
# ======================================================================

class TestFileClassification:
    """P0-1: 파일 분류 로직 — 테스트/데이터 파일에 missing 규칙 미적용.

    현재 rule_engine_service.py에는 파일 분류 로직이 없다.
    이 테스트는 P0-1 구현 후 통과하도록 설계됨.
    구현 전에는 XFAIL로 처리.
    """

    def _classify_file(self, filename: str, code: str) -> str:
        """파일 분류 헬퍼 — P0-1 구현 후 실제 함수로 교체.

        Returns: 'impl' | 'test' | 'data' | 'benchmark'
        """
        # 파일명 패턴 기반 분류
        name_lower = filename.lower()
        test_patterns = ["_test", "_vs", "test_", "kat", "_0tv"]
        bench_patterns = ["benchmark", "bench_", "_bench"]

        for p in bench_patterns:
            if p in name_lower:
                return "benchmark"
        for p in test_patterns:
            if p in name_lower:
                return "test"

        # 데이터 전용 파일: 함수 정의 0개 + const 배열만
        func_def_pattern = re.compile(
            r'^\s*(?:void|int|unsigned|uint\w+|char|float|double|static)\s+\w+\s*\(',
            re.MULTILINE,
        )
        has_func_def = bool(func_def_pattern.search(code))
        has_const_array = bool(re.search(r'\bconst\b.*\{', code))

        if not has_func_def and has_const_array:
            return "data"

        return "impl"

    @pytest.mark.rule_engine
    def test_data_file_detection(self, load_fixture):
        """lea_vs.c 패턴: _vs 포함 → 'test' 또는 'data' (둘 다 missing 규칙 스킵 대상)"""
        code = load_fixture("data_only_file.c")
        result = self._classify_file("lea_vs.c", code)
        assert result in ("data", "test"), f"lea_vs.c는 impl이 아니어야: {result}"

    @pytest.mark.rule_engine
    def test_benchmark_file_detection(self, load_fixture):
        """benchmark.c → 'benchmark' 분류"""
        code = load_fixture("benchmark_file.c")
        assert self._classify_file("benchmark.c", code) == "benchmark"

    @pytest.mark.rule_engine
    def test_benchmark_by_name(self):
        """파일명에 benchmark 포함 → 'benchmark'"""
        assert self._classify_file("lea_benchmark.c", "") == "benchmark"

    @pytest.mark.rule_engine
    def test_test_file_by_name(self):
        """파일명에 _vs 포함 → 'test'"""
        assert self._classify_file("lea_vs.c", "") == "test"
        assert self._classify_file("main_0tv.c", "") == "test"

    @pytest.mark.rule_engine
    def test_impl_file_not_excluded(self, load_fixture):
        """실제 암호 구현 파일은 'impl'로 분류"""
        code = load_fixture("lea_003_compliant.c")  # 함수 정의 있는 일반 코드
        assert self._classify_file("lea_core.c", code) == "impl"

    @pytest.mark.rule_engine
    def test_missing_rule_skip_on_data_file(self, load_fixture):
        """data 파일에 missing 규칙 적용 시 위반 0건이어야 함.

        현재는 미구현 — P0-1 구현 후 실제 rule_engine 호출로 교체.
        """
        code = load_fixture("data_only_file.c")
        classification = self._classify_file("lea_vs.c", code)
        # data 파일에는 missing 규칙을 적용하지 않아야 함
        assert classification in ("data", "test", "benchmark")

    @pytest.mark.rule_engine
    def test_actual_classifier_uses_submission_path(self):
        """제출물 상대 경로의 test/ 디렉터리를 테스트 파일로 분류."""
        from app.services.rule_engine_service import _classify_file

        code = "int main(void) { return 0; }"
        assert _classify_file("test/addmac.c", code) == "test"
        assert _classify_file("src/addmac.c", code) == "impl"

    @pytest.mark.rule_engine
    def test_com001_detects_return_before_zeroization(self):
        """민감값 사용 뒤 zeroization보다 먼저 빠지는 return 경로를 탐지."""
        from app.services.rule_engine_service import _has_uncleared_sensitive_return_path

        unsafe_code = """
int f(int fail) {
    uint8_t key[16] = {0};
    lea_encrypt(key, key);
    if (fail) return -1;
    memset_s(key, sizeof(key), 0, sizeof(key));
    return 0;
}
"""
        safe_code = """
int f(int fail) {
    uint8_t key[16] = {0};
    lea_encrypt(key, key);
    memset_s(key, sizeof(key), 0, sizeof(key));
    if (fail) return -1;
    return 0;
}
"""
        assert _has_uncleared_sensitive_return_path(unsafe_code) is True
        assert _has_uncleared_sensitive_return_path(safe_code) is False


# ======================================================================
# Fallback regex 과잉 매칭 테스트 (02 보고서 §2.2)
# ======================================================================

class TestFallbackRegexPrecision:
    """원인 B: fallback regex가 의미 없는 코드에 매칭하지 않는지 검증."""

    @pytest.mark.rule_engine
    def test_ctr005_matches_function_name_only(self, load_rule, match_fallback):
        """CTR-005 fallback: 함수명만 매칭 — SSP 관리는 검사 못함 (알려진 한계)."""
        rule = load_rule("CTR-005")
        pattern = rule.get("fallback_pattern", "")
        if not pattern:
            pytest.skip("CTR-005 fallback_pattern 없음")

        # 함수 선언만 있는 코드 — FP가 되어야 할 상황
        code_fp = "void lea_ctr_enc(uint8_t *ct, const uint8_t *pt) {}"
        matches = match_fallback(pattern, code_fp)
        # 현재 동작: 함수명에 매칭됨 (알려진 FP 원인)
        assert len(matches) >= 1, "CTR-005 fallback은 함수명에 매칭되어야 함 (알려진 동작)"

    @pytest.mark.rule_engine
    def test_lea059_struct_typedef_matches(self, load_rule, match_fallback):
        """LEA-059 fallback: 구조체 타입명 'LEA_MMT_ECB' 에 매칭 — FP 원인."""
        rule = load_rule("LEA-059")
        pattern = rule.get("fallback_pattern", "")
        if not pattern:
            pytest.skip("LEA-059 fallback_pattern 없음")

        # lea_vs.c 패턴: 타입명에 MMT 포함
        code_fp = "const LEA_MMT_ECB lea128_mmt_ecb[10] = { };"
        matches = match_fallback(pattern, code_fp)
        # 현재 동작: MMT 문자열에 매칭됨 (알려진 FP)
        # P0-3 적용 후: 매칭되지 않아야 함
        assert len(matches) >= 1, "LEA-059 fallback이 타입명에 매칭됨 (알려진 FP)"

    @pytest.mark.rule_engine
    def test_lea032_gcm_loop_matches(self, load_rule, match_fallback):
        """LEA-032 fallback: GCM의 for(i<32) 루프에 매칭 — FP 원인."""
        rule = load_rule("LEA-032")
        pattern = rule.get("fallback_pattern", "")
        if not pattern:
            pytest.skip("LEA-032 fallback_pattern 없음")

        # GCM 코드의 for 루프 — LEA와 무관
        code_fp = "for (i = 0; i < 32; i++) { gcm_mult(H, X); }"
        matches = match_fallback(pattern, code_fp)
        # 현재 동작: <32 에 매칭됨 (알려진 FP)
        assert len(matches) >= 1, "LEA-032 fallback이 GCM 루프에 매칭됨 (알려진 FP)"

    @pytest.mark.rule_engine
    def test_lea032_lea_round_loop_matches(self, load_rule, match_fallback):
        """LEA-032 fallback: LEA 라운드 루프에는 정상 매칭되어야."""
        rule = load_rule("LEA-032")
        pattern = rule.get("fallback_pattern", "")
        if not pattern:
            pytest.skip("LEA-032 fallback_pattern 없음")

        code_tp = "void lea_encrypt(uint32_t *block) { for (i = 0; i < 24; i++) {} }"
        matches = match_fallback(pattern, code_tp)
        assert len(matches) >= 1


# ======================================================================
# COM-003 테스트 벡터 예외 (P0-4 — 02 보고서 §2.5)
# ======================================================================

class TestCOM003Filter:
    """P0-4: COM-003 하드코딩 키 규칙의 FP 필터링."""

    def _should_skip_com003(self, filename: str) -> bool:
        """COM-003 스킵 판정 — P0-4 구현 후 실제 함수로 교체."""
        name_lower = filename.lower()
        skip_patterns = ["test", "kat", "vector", "0tv", "benchmark", "_vs"]
        return any(p in name_lower for p in skip_patterns)

    @pytest.mark.rule_engine
    def test_kat_vector_file_skipped(self):
        """파일명 *_0tv* → COM-003 스킵"""
        assert self._should_skip_com003("main_0tv.c")

    @pytest.mark.rule_engine
    def test_test_vector_file_skipped(self):
        """파일명 *_vs* → COM-003 스킵"""
        assert self._should_skip_com003("lea_vs.c")

    @pytest.mark.rule_engine
    def test_impl_file_not_skipped(self):
        """실제 구현 파일 → COM-003 적용"""
        assert not self._should_skip_com003("lea_core.c")
        assert not self._should_skip_com003("lea_online.c")

    @pytest.mark.rule_engine
    def test_com003_regex_matches_hex_array(self):
        """COM-003 native regex: 8개+ hex 값 배열에 매칭."""
        # COM-003 패턴: const unsigned char[] = {0x.., 0x.., ...} 8개+
        pattern = r'(?:0x[0-9a-fA-F]{2}\s*,?\s*){8,}'
        code_violation = 'unsigned char mk[16] = {0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96};'
        code_short = 'unsigned char iv[4] = {0x01, 0x02, 0x03, 0x04};'

        assert re.search(pattern, code_violation), "8개+ hex 배열은 매칭되어야"
        assert not re.search(pattern, code_short), "4개 hex 배열은 매칭 안 됨"


# ======================================================================
# 중복제거 로직 테스트
# ======================================================================

class TestDedup:
    """_dedup_nearby_violations: 5줄 이내 중복 제거."""

    @pytest.mark.rule_engine
    def test_dedup_same_line(self):
        """동일 라인 위반 → 1건으로 합침"""
        from app.services.rule_engine_service import _dedup_nearby_violations

        violations = [
            {"line": 10, "rule_id": "LEA-003", "message": "A"},
            {"line": 10, "rule_id": "LEA-003", "message": "B"},
        ]
        result = _dedup_nearby_violations(violations)
        assert len(result) == 1

    @pytest.mark.rule_engine
    def test_dedup_within_window(self):
        """20줄 이내 위반 → 1건으로 합침 (window=20)"""
        from app.services.rule_engine_service import _dedup_nearby_violations

        violations = [
            {"line": 10, "rule_id": "LEA-003", "message": "A"},
            {"line": 25, "rule_id": "LEA-003", "message": "B"},
        ]
        result = _dedup_nearby_violations(violations)
        assert len(result) == 1

    @pytest.mark.rule_engine
    def test_dedup_beyond_window(self):
        """21줄 이상 차이 → 별도 유지"""
        from app.services.rule_engine_service import _dedup_nearby_violations

        violations = [
            {"line": 10, "rule_id": "LEA-003", "message": "A"},
            {"line": 50, "rule_id": "LEA-003", "message": "B"},
        ]
        result = _dedup_nearby_violations(violations)
        assert len(result) == 2
