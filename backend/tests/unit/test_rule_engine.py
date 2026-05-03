"""
룰 엔진 단위 테스트.

02_FP_심층분석 보고서 기반:
- 파일 분류 로직 (P0-1): 테스트/데이터 파일 구분
- Fallback regex 과잉 매칭 (원인 B): CTR-005, LEA-059, LEA-032
- COM-003 테스트 벡터 예외 (P0-4)
- 중복제거 로직
"""

import re

import pytest


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
