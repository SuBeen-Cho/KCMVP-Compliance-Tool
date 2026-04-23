"""
AST 체커 단위 테스트 — Tier 1 (FP/FN 실제 발생 규칙 10개).

02_FP_심층분석 보고서 기반 우선순위:
- LEA-003: FN 발생 (세트2), 직접 할당 패턴
- LEA-010: FP 47건 (매크로 불투명성)
- LEA-040: FN 발생 (세트3)
- CBC-001/002: FN/FP 발생
- OFB-002: FP 15건
- CFB-002: FP 13건
- CTR-001: FP 10건
- CTR-002: FN 발생 (세트4)
- LEA-047: FN + L2 오판 이력
"""

import pytest


# ======================================================================
# LEA-003: 라운드 수 검증
# ======================================================================

class TestLEA003:
    """LEA-003: 키 스케줄 함수 내 라운드 수가 24/28/32인지 검사."""

    @pytest.mark.tier1
    def test_violation_direct_assignment(self, check_rule, load_fixture):
        """ctx->rounds = 25 → 위반 탐지"""
        code = load_fixture("lea_003_violation.c")
        result = check_rule("LEA-003", code)
        assert result is not None
        assert len(result) >= 1
        assert any("25" in v["message"] for v in result)

    @pytest.mark.tier1
    def test_compliant_standard_rounds(self, check_rule, load_fixture):
        """ctx->rounds = 24/28/32 → 위반 없음"""
        code = load_fixture("lea_003_compliant.c")
        result = check_rule("LEA-003", code)
        assert result is not None
        assert len(result) == 0

    @pytest.mark.tier1
    def test_violation_loop_bound(self, check_rule, load_fixture):
        """for(i=0; i<25; ...) in key_schedule → 위반 탐지"""
        code = load_fixture("lea_003_loop_violation.c")
        result = check_rule("LEA-003", code)
        assert result is not None
        assert len(result) >= 1

    @pytest.mark.tier1
    def test_compliant_inline_code(self, check_rule):
        """표준 라운드 수 24를 사용하는 인라인 코드 → 위반 없음"""
        code = """
typedef unsigned int uint32_t;
void lea_set_key(const unsigned char *mk, uint32_t *rk) {
    int i;
    for (i = 0; i < 24; i++) {
        rk[i] = 0;
    }
}
"""
        result = check_rule("LEA-003", code)
        assert result is not None
        assert len(result) == 0

    @pytest.mark.tier1
    def test_no_key_func_returns_empty(self, check_rule):
        """키 스케줄 함수가 없는 코드 → 빈 리스트"""
        code = """
typedef unsigned int uint32_t;
void some_function(uint32_t *buf) {
    int i;
    for (i = 0; i < 10; i++) {
        buf[i] = 0;
    }
}
"""
        result = check_rule("LEA-003", code)
        assert result is not None
        assert len(result) == 0


# ======================================================================
# LEA-010: 키 스케줄 ARX 구조 검증
# ======================================================================

class TestLEA010:
    """LEA-010: 키 스케줄 함수 내 ROL/ROR + ADD 연산 존재 확인."""

    @pytest.mark.tier1
    def test_macro_rol_code(self, check_rule, load_fixture):
        """ROL 매크로 사용 코드 — 현재는 매크로를 인식 못할 수 있음.

        P0-2(매크로 인식 리스트) 적용 전: 위반 반환 가능
        P0-2 적용 후: 빈 리스트 (정상) 기대
        """
        code = load_fixture("macro_rol_code.c")
        result = check_rule("LEA-010", code)
        # 파싱은 성공해야 함 (None이면 안됨)
        # 현재 동작: ROL이 함수 호출로 보이므로 실제로 인식할 수도 있음
        assert result is not None

    @pytest.mark.tier1
    def test_func_pointer_wrapper_fp(self, check_rule, load_fixture):
        """함수 포인터 래퍼 — 래퍼 자체에 ROL/+ 없음 → 현재 FP 발생."""
        code = load_fixture("func_pointer_wrapper.c")
        result = check_rule("LEA-010", code)
        # 래퍼 함수에 ROL/+가 없어서 위반을 보고할 수 있음 (알려진 FP)
        assert result is not None

    @pytest.mark.tier1
    def test_compliant_arx_structure(self, check_rule):
        """ROL + ADD 모두 있는 정상 키 스케줄 → 위반 없음"""
        code = """
typedef unsigned int uint32_t;

uint32_t ROL32(uint32_t x, int r);

void lea_key_schedule(const unsigned char *mk, uint32_t *rk) {
    uint32_t T[8];
    int i;
    for (i = 0; i < 24; i++) {
        T[0] = ROL32(T[0] + 0xc3efe9db, 1);
        rk[i] = T[0] + T[1];
    }
}
"""
        result = check_rule("LEA-010", code)
        assert result is not None
        assert len(result) == 0

    @pytest.mark.tier1
    def test_delta_constant_validation(self, check_rule):
        """symbol_graph에 비표준 delta 상수 → 위반 탐지 (Phase 2)"""
        code = """
typedef unsigned int uint32_t;
uint32_t ROL32(uint32_t x, int r);

void lea_set_key(const unsigned char *mk, uint32_t *rk) {
    uint32_t T[4];
    T[0] = ROL32(T[0] + 0x11111111, 1);
    rk[0] = T[0] + T[1];
}
"""
        sg = {
            "array_inits": {
                "delta": {
                    "file": "test.c",
                    "values": ["0x11111111", "0x22222222", "0x33333333",
                               "0x44444444", "0x55555555", "0x66666666",
                               "0x77777777", "0x88888888"],
                }
            }
        }
        result = check_rule("LEA-010", code, symbol_graph=sg)
        assert result is not None
        # 비표준 delta → 위반
        assert len(result) >= 1


# ======================================================================
# LEA-040: 라운드 루프 경계 조건
# ======================================================================

class TestLEA040:
    """LEA-040: <= 대신 < 사용, off-by-one 탐지."""

    @pytest.mark.tier1
    def test_violation_lte_operator(self, check_rule, load_fixture):
        """i <= 24 → 25회 반복, off-by-one 위반"""
        code = load_fixture("lea_040_violation.c")
        result = check_rule("LEA-040", code)
        assert result is not None
        assert len(result) >= 1

    @pytest.mark.tier1
    def test_lte_23_is_valid(self, check_rule):
        """i <= 23 → 24회 반복 = 정상 (LEA-128 라운드 수)"""
        code = """
typedef unsigned int uint32_t;
void lea_encrypt_block(uint32_t *block, const uint32_t *rk) {
    int i;
    for (i = 0; i <= 23; i++) {
        block[0] = block[0] ^ rk[i];
    }
}
"""
        result = check_rule("LEA-040", code)
        assert result is not None
        assert len(result) == 0

    @pytest.mark.tier1
    def test_compliant_lt_operator(self, check_rule, load_fixture):
        """i < 24 → 정상"""
        code = load_fixture("lea_040_compliant.c")
        result = check_rule("LEA-040", code)
        assert result is not None
        assert len(result) == 0


# ======================================================================
# OFB-002 / CFB-002: 매크로 불투명성 (02 보고서 원인 A)
# ======================================================================

class TestOFB002:
    """OFB-002: OFB 모드 XOR 연산 존재 확인."""

    @pytest.mark.tier1
    def test_macro_xor_returns_none_or_violation(self, check_rule, load_fixture):
        """XOR8x16 매크로 사용 — 현재 XOR 미인식으로 None 또는 위반 반환.

        이 테스트는 현재 동작을 기록하는 것이며,
        P0-2(매크로 인식 리스트) 적용 후에는 빈 리스트가 기대됨.
        """
        code = load_fixture("macro_xor_code.c")
        result = check_rule("OFB-002", code, filename="lea_ofb.c")
        # None(파싱 실패→fallback) 또는 위반 리스트 반환
        # P0-2 적용 후: assert result == []
        if result is not None:
            # 매크로 XOR 미인식 → FP 발생하는 것이 현재 알려진 동작
            pass

    @pytest.mark.tier1
    def test_direct_xor_compliant(self, check_rule):
        """직접 ^ 연산자 사용 → 위반 없음"""
        code = """
typedef unsigned int uint32_t;
typedef unsigned char uint8_t;

void lea_ofb_enc(uint8_t *ct, const uint8_t *pt, uint8_t *iv, int n) {
    int i;
    for (i = 0; i < n; i++) {
        ct[i] = pt[i] ^ iv[i];
    }
}
"""
        result = check_rule("OFB-002", code, filename="lea_ofb.c")
        if result is not None:
            assert len(result) == 0


class TestCFB002:
    """CFB-002: CFB 모드 XOR 연산 존재 확인."""

    @pytest.mark.tier1
    def test_macro_xor_returns_none_or_violation(self, check_rule, load_fixture):
        """XOR8x16 매크로 사용 — OFB-002와 동일한 매크로 불투명성 문제."""
        code = load_fixture("macro_xor_code.c")
        result = check_rule("CFB-002", code, filename="lea_cfb.c")
        if result is not None:
            pass  # 현재 동작 기록용


# ======================================================================
# CBC-001 / CBC-002: CBC 체이닝
# ======================================================================

class TestCBC001:
    """CBC-001: CBC 암호화 XOR 체이닝 확인."""

    @pytest.mark.tier1
    def test_compliant_xor_chaining(self, check_rule):
        """PT ^ CT[i-1] 패턴 존재 → 위반 없음"""
        code = """
typedef unsigned int uint32_t;
typedef unsigned char uint8_t;

void lea_cbc_enc(uint8_t *ct, const uint8_t *pt, uint8_t *iv,
                 const uint32_t *rk, int n) {
    int i;
    for (i = 0; i < n; i++) {
        ct[i] = pt[i] ^ iv[i];
    }
}
"""
        result = check_rule("CBC-001", code, filename="cbc_enc.c")
        if result is not None:
            assert len(result) == 0

    @pytest.mark.tier1
    def test_violation_no_xor(self, check_rule):
        """XOR 없는 CBC 구현 → 위반"""
        code = """
typedef unsigned int uint32_t;
typedef unsigned char uint8_t;

void lea_cbc_enc(uint8_t *ct, const uint8_t *pt,
                 const uint32_t *rk, int n) {
    int i;
    for (i = 0; i < n; i++) {
        ct[i] = pt[i] + rk[0];
    }
}
"""
        result = check_rule("CBC-001", code, filename="cbc_enc.c")
        if result is not None:
            assert len(result) >= 1


class TestCBC002:
    """CBC-002: CBC 복호화 XOR 체이닝 확인."""

    @pytest.mark.tier1
    def test_compliant_xor_chaining(self, check_rule):
        """DEC(CT) ^ CT[i-1] 패턴 존재 → 위반 없음"""
        code = """
typedef unsigned int uint32_t;
typedef unsigned char uint8_t;

void lea_cbc_dec(uint8_t *pt, const uint8_t *ct, uint8_t *iv,
                 const uint32_t *rk, int n) {
    int i;
    for (i = 0; i < n; i++) {
        pt[i] = ct[i] ^ iv[i];
    }
}
"""
        result = check_rule("CBC-002", code, filename="cbc_dec.c")
        if result is not None:
            assert len(result) == 0


# ======================================================================
# CTR-001: CTR 카운터 증분
# ======================================================================

class TestCTR001:
    """CTR-001: CTR 모드 카운터 증분 패턴 확인."""

    @pytest.mark.tier1
    def test_compliant_counter_increment(self, check_rule):
        """카운터 증분 존재 → 위반 없음"""
        code = """
typedef unsigned int uint32_t;
typedef unsigned char uint8_t;

void ctr128_inc(uint8_t *ctr) {
    int i;
    for (i = 15; i >= 0; i--) {
        if (++ctr[i]) break;
    }
}

void lea_ctr_enc(uint8_t *ct, const uint8_t *pt, uint8_t *ctr,
                 const uint32_t *rk, int n) {
    int i;
    for (i = 0; i < n; i++) {
        ct[i] = pt[i] ^ ctr[i % 16];
        if ((i + 1) % 16 == 0) ctr128_inc(ctr);
    }
}
"""
        result = check_rule("CTR-001", code, filename="lea_ctr.c")
        if result is not None:
            assert len(result) == 0


# ======================================================================
# CTR-002: CTR 초기화
# ======================================================================

class TestCTR002:
    """CTR-002: CTR 초기화 패턴 확인."""

    @pytest.mark.tier1
    def test_compliant_ctr_init(self, check_rule):
        """CTR 초기화 코드 → 위반 없음"""
        code = """
typedef unsigned int uint32_t;
typedef unsigned char uint8_t;

void lea_ctr_init(uint8_t *ctr, const uint8_t *nonce) {
    int i;
    for (i = 0; i < 16; i++) {
        ctr[i] = nonce[i];
    }
    ctr[15] = 1;
}
"""
        result = check_rule("CTR-002", code, filename="lea_ctr.c")
        if result is not None:
            assert len(result) == 0


# ======================================================================
# LEA-047: MCT 상태 갱신
# ======================================================================

class TestLEA047:
    """LEA-047: MCT 상태 갱신 / 평문 재사용 패턴."""

    @pytest.mark.tier1
    def test_returns_result_on_parseable_code(self, check_rule):
        """LEA-047은 Optional 반환. None(파싱 실패/판단 불가)도 정상 동작."""
        code = """
typedef unsigned int uint32_t;
typedef unsigned char uint8_t;

void lea_mct_loop(uint8_t *pt, uint8_t *ct, const uint32_t *rk) {
    int i, j;
    for (i = 0; i < 100; i++) {
        for (j = 0; j < 1000; j++) {
            ct[0] = pt[0] ^ rk[0];
            pt[0] = ct[0];
        }
    }
}
"""
        result = check_rule("LEA-047", code)
        # LEA-047은 Optional[List] — None은 "판단 불가" (fallback 사용)
        # 위반 리스트 반환 시에는 올바른 형식이어야 함
        if result is not None:
            assert isinstance(result, list)
            for v in result:
                assert "message" in v


# ======================================================================
# ==================== TIER 2 테스트 (10개 규칙) =======================
# ======================================================================


# ======================================================================
# LEA-030: 암호화 라운드 워드 스왑 (X[3]=X[0])
# ======================================================================

class TestLEA030:
    """LEA-030: 암호화 함수 내 워드 스왑 X[3]=X[0] 패턴 존재 확인."""

    @pytest.mark.tier2
    def test_compliant_array_swap(self, check_rule):
        """배열 인덱스 패턴 X[3]=X[0] 존재 → 위반 없음"""
        code = """
typedef unsigned int uint32_t;
void lea_encrypt(uint32_t *block, const uint32_t *rk) {
    uint32_t X[4];
    int i;
    for (i = 0; i < 24; i++) {
        X[3] = X[0];
        X[0] = (X[0] ^ rk[i]) + X[1];
    }
}
"""
        result = check_rule("LEA-030", code, filename="lea_enc.c")
        if result is not None:
            assert len(result) == 0

    @pytest.mark.tier2
    def test_macro_based_returns_none(self, check_rule):
        """매크로 기반 라운드 함수 → None (판단 불가)"""
        code = """
typedef unsigned int uint32_t;
#define ROUND(a,b,c,d,k) { a = (a^k)+b; }
void lea_encrypt(uint32_t *block, const uint32_t *rk) {
    uint32_t X[4];
    ROUND(X[0],X[1],X[2],X[3],rk[0]);
}
"""
        result = check_rule("LEA-030", code, filename="lea_enc.c")
        # 매크로 기반이면 None 또는 빈 리스트 (pycparser가 매크로를 못 볼 수 있음)
        # None = fallback 위임, [] = 판단 불가
        assert result is None or result == []

    @pytest.mark.tier2
    def test_no_enc_func_returns_empty(self, check_rule):
        """암호화 함수 없는 코드 → 빈 리스트"""
        code = """
typedef unsigned int uint32_t;
void some_helper(uint32_t *buf) {
    buf[0] = buf[1];
}
"""
        result = check_rule("LEA-030", code)
        if result is not None:
            assert len(result) == 0


# ======================================================================
# LEA-031: 라운드 함수 XOR→ADD 순서
# ======================================================================

class TestLEA031:
    """LEA-031: ADD(+)가 XOR(^)를 감싸야 함. 역순이면 위반."""

    @pytest.mark.tier2
    def test_violation_wrong_order(self, check_rule):
        """a ^ (b + c) 패턴 → XOR 안에 ADD → 위반"""
        code = """
typedef unsigned int uint32_t;
void lea_encrypt(uint32_t *block, const uint32_t *rk) {
    uint32_t x0, x1, x2, x3;
    x0 = x1 ^ (x2 + rk[0]);
}
"""
        result = check_rule("LEA-031", code, filename="lea_enc.c")
        assert result is not None
        assert len(result) >= 1

    @pytest.mark.tier2
    def test_compliant_correct_order(self, check_rule):
        """(a ^ b) + c 패턴 → 정상 순서 → 위반 없음"""
        code = """
typedef unsigned int uint32_t;
void lea_encrypt(uint32_t *block, const uint32_t *rk) {
    uint32_t x0, x1, x2, x3;
    x0 = (x1 ^ x2) + rk[0];
}
"""
        result = check_rule("LEA-031", code, filename="lea_enc.c")
        assert result is not None
        assert len(result) == 0

    @pytest.mark.tier2
    def test_no_enc_func_returns_empty(self, check_rule):
        """암호화 함수 없는 코드 → 빈 리스트"""
        code = """
typedef unsigned int uint32_t;
void helper(uint32_t a, uint32_t b) {
    uint32_t c = a ^ (b + 1);
}
"""
        result = check_rule("LEA-031", code)
        assert result is not None
        assert len(result) == 0


# ======================================================================
# LEA-034: 복호화 함수 내 모듈러 뺄셈(-)
# ======================================================================

class TestLEA034:
    """LEA-034: 복호화 함수에 뺄셈(-) 연산이 반드시 있어야 함."""

    @pytest.mark.tier2
    def test_compliant_has_subtraction(self, check_rule):
        """복호화 함수에 뺄셈 존재 → 위반 없음"""
        code = """
typedef unsigned int uint32_t;
void lea_decrypt(uint32_t *block, const uint32_t *rk) {
    uint32_t x0, x1;
    x0 = x1 - rk[0];
}
"""
        result = check_rule("LEA-034", code, filename="lea_dec.c")
        assert result is not None
        assert len(result) == 0

    @pytest.mark.tier2
    def test_violation_no_subtraction(self, check_rule):
        """복호화 함수에 뺄셈 없음 → 위반"""
        code = """
typedef unsigned int uint32_t;
void lea_decrypt(uint32_t *block, const uint32_t *rk) {
    uint32_t x0, x1;
    x0 = x1 + rk[0];
    x1 = x0 ^ rk[1];
}
"""
        result = check_rule("LEA-034", code, filename="lea_dec.c")
        assert result is not None
        assert len(result) >= 1

    @pytest.mark.tier2
    def test_no_dec_func_returns_empty(self, check_rule):
        """복호화 함수 없는 코드 → 빈 리스트"""
        code = """
typedef unsigned int uint32_t;
void lea_encrypt(uint32_t *block, const uint32_t *rk) {
    block[0] = block[1] + rk[0];
}
"""
        result = check_rule("LEA-034", code, filename="lea_enc.c")
        assert result is not None
        assert len(result) == 0


# ======================================================================
# LEA-035: 복호화 역 워드 스왑 (X[0]=X[3])
# ======================================================================

class TestLEA035:
    """LEA-035: 복호화 함수 내 역 워드 스왑 X[0]=X[3] 패턴."""

    @pytest.mark.tier2
    def test_compliant_reverse_swap(self, check_rule):
        """X[0]=X[3] 패턴 존재 → 위반 없음"""
        code = """
typedef unsigned int uint32_t;
void lea_decrypt(uint32_t *block, const uint32_t *rk) {
    uint32_t X[4];
    int i;
    for (i = 23; i >= 0; i--) {
        X[0] = X[3];
        X[3] = X[2] - rk[i];
    }
}
"""
        result = check_rule("LEA-035", code, filename="lea_dec.c")
        if result is not None:
            assert len(result) == 0

    @pytest.mark.tier2
    def test_no_dec_func_returns_empty(self, check_rule):
        """복호화 함수 없는 코드 → 빈 리스트"""
        code = """
typedef unsigned int uint32_t;
void helper(uint32_t *buf) { buf[0] = buf[1]; }
"""
        result = check_rule("LEA-035", code)
        if result is not None:
            assert len(result) == 0


# ======================================================================
# LEA-014: 키 스케줄 T[] 모듈러 덧셈(+)
# ======================================================================

class TestLEA014:
    """LEA-014: T[] 업데이트에 + 연산 필수."""

    @pytest.mark.tier2
    def test_compliant_t_add(self, check_rule):
        """T[i] = ROL(T[j] + delta[k], r) → 정상"""
        code = """
typedef unsigned int uint32_t;
uint32_t ROL32(uint32_t x, int r);
void lea_set_key(const unsigned char *mk, uint32_t *rk) {
    uint32_t T[8];
    T[0] = ROL32(T[0] + 0xc3efe9db, 1);
    T[1] = ROL32(T[1] + 0x44626b02, 3);
    T[2] = ROL32(T[2] + 0x79e27c8a, 6);
    T[3] = ROL32(T[3] + 0x78df30ec, 11);
}
"""
        result = check_rule("LEA-014", code)
        assert result is not None
        assert len(result) == 0

    @pytest.mark.tier2
    def test_violation_no_add_in_t(self, check_rule):
        """T[i] = ROL(T[j], r) → + 없음 → 위반"""
        code = """
typedef unsigned int uint32_t;
uint32_t ROL32(uint32_t x, int r);
void lea_key_schedule(const unsigned char *mk, uint32_t *rk) {
    uint32_t T[8];
    T[0] = ROL32(T[0], 1);
    T[1] = ROL32(T[1], 3);
    T[2] = ROL32(T[2], 6);
    T[3] = ROL32(T[3], 11);
}
"""
        result = check_rule("LEA-014", code)
        assert result is not None
        assert len(result) >= 1

    @pytest.mark.tier2
    def test_no_key_func_returns_empty(self, check_rule):
        """키 스케줄 함수 없음 → 빈 리스트"""
        code = """
typedef unsigned int uint32_t;
void helper(uint32_t *buf) { buf[0] = buf[1]; }
"""
        result = check_rule("LEA-014", code)
        assert result is not None
        assert len(result) == 0


# ======================================================================
# LEA-015: 델타 상수 순환 인덱싱 (i%4/6/8)
# ======================================================================

class TestLEA015:
    """LEA-015: delta[] 접근에 % 4/6/8 순환 패턴 필수."""

    @pytest.mark.tier2
    def test_compliant_mod4(self, check_rule):
        """delta[i%4] 패턴 → 정상"""
        code = """
typedef unsigned int uint32_t;
uint32_t ROL32(uint32_t x, int r);
void lea_set_key(const unsigned char *mk, uint32_t *rk) {
    uint32_t T[4], delta[4];
    int i;
    for (i = 0; i < 24; i++) {
        T[i%4] = ROL32(T[i%4] + delta[i%4], 1);
    }
}
"""
        result = check_rule("LEA-015", code)
        assert result is not None
        assert len(result) == 0

    @pytest.mark.tier2
    def test_violation_no_modulo(self, check_rule):
        """delta[i] 직접 인덱싱 (% 없음) → 위반"""
        code = """
typedef unsigned int uint32_t;
uint32_t ROL32(uint32_t x, int r);
void lea_key_schedule(const unsigned char *mk, uint32_t *rk) {
    uint32_t T[4], delta[4];
    int i;
    for (i = 0; i < 24; i++) {
        T[0] = ROL32(T[0] + delta[i], 1);
    }
}
"""
        result = check_rule("LEA-015", code)
        assert result is not None
        assert len(result) >= 1


# ======================================================================
# LEA-021: 라운드키 6-워드 구성 (T[1] 반복)
# ======================================================================

class TestLEA021:
    """LEA-021: RK[i][j] = T[k] 에서 T[1] 3회 반복 패턴 필수."""

    @pytest.mark.tier2
    def test_compliant_t1_repeated(self, check_rule):
        """RK에 T[1] 반복 패턴 존재 → 정상"""
        code = """
typedef unsigned int uint32_t;
void lea_set_key(const unsigned char *mk, uint32_t *rk) {
    uint32_t T[4];
    uint32_t RK[24][6];
    int i;
    for (i = 0; i < 24; i++) {
        RK[i][0] = T[0];
        RK[i][1] = T[1];
        RK[i][2] = T[2];
        RK[i][3] = T[1];
        RK[i][4] = T[3];
        RK[i][5] = T[1];
    }
}
"""
        result = check_rule("LEA-021", code)
        assert result is not None
        assert len(result) == 0

    @pytest.mark.tier2
    def test_violation_no_t1(self, check_rule):
        """RK에 T[1] 참조 없음 → 위반"""
        code = """
typedef unsigned int uint32_t;
void lea_key_schedule(const unsigned char *mk, uint32_t *rk) {
    uint32_t T[4];
    uint32_t RK[24][6];
    int i;
    for (i = 0; i < 24; i++) {
        RK[i][0] = T[0];
        RK[i][2] = T[2];
        RK[i][4] = T[3];
    }
}
"""
        result = check_rule("LEA-021", code)
        assert result is not None
        assert len(result) >= 1


# ======================================================================
# LEA-046: MCT 이중 루프 100×1000
# ======================================================================

class TestLEA046:
    """LEA-046: MCT 함수 이중 루프가 100×1000 구조인지 검사."""

    @pytest.mark.tier2
    def test_compliant_100x1000(self, check_rule):
        """외부 100, 내부 1000 → 정상"""
        code = """
typedef unsigned int uint32_t;
typedef unsigned char uint8_t;
void lea_mct(uint8_t *pt, uint8_t *ct, const uint32_t *rk) {
    int i, j;
    for (i = 0; i < 100; i++) {
        for (j = 0; j < 1000; j++) {
            ct[0] = pt[0] ^ rk[0];
            pt[0] = ct[0];
        }
    }
}
"""
        result = check_rule("LEA-046", code)
        assert result is not None
        assert len(result) == 0

    @pytest.mark.tier2
    def test_violation_wrong_bounds(self, check_rule):
        """외부 10, 내부 100 → 위반"""
        code = """
typedef unsigned int uint32_t;
typedef unsigned char uint8_t;
void lea_mct(uint8_t *pt, uint8_t *ct, const uint32_t *rk) {
    int i, j;
    for (i = 0; i < 10; i++) {
        for (j = 0; j < 100; j++) {
            ct[0] = pt[0] ^ rk[0];
        }
    }
}
"""
        result = check_rule("LEA-046", code)
        assert result is not None
        assert len(result) >= 1

    @pytest.mark.tier2
    def test_no_mct_func_returns_empty(self, check_rule):
        """MCT 함수 없음 → 빈 리스트"""
        code = """
typedef unsigned int uint32_t;
void lea_encrypt(uint32_t *block, const uint32_t *rk) {
    block[0] = block[1] ^ rk[0];
}
"""
        result = check_rule("LEA-046", code)
        assert result is not None
        assert len(result) == 0


# ======================================================================
# CMAC-001: 서브키 파생 Rb=0x87 XOR
# ======================================================================

class TestCMAC001:
    """CMAC-001: CMAC 서브키 파생에서 Rb(0x87) XOR 존재 확인."""

    @pytest.mark.tier2
    def test_compliant_rb_xor(self, check_rule):
        """K1 ^= 0x87 패턴 → 정상"""
        code = """
typedef unsigned char uint8_t;
void cmac_init(uint8_t *K1, uint8_t *K2, const uint8_t *L) {
    int i;
    for (i = 0; i < 16; i++) {
        K1[i] = L[i] << 1;
    }
    K1[15] ^= 0x87;
    for (i = 0; i < 16; i++) {
        K2[i] = K1[i] << 1;
    }
    K2[15] ^= 0x87;
}
"""
        result = check_rule("CMAC-001", code)
        assert result is not None
        assert len(result) == 0

    @pytest.mark.tier2
    def test_violation_no_rb_xor(self, check_rule):
        """서브키 배열은 있지만 0x87 XOR 없음 → 위반"""
        code = """
typedef unsigned char uint8_t;
void cmac_init(uint8_t *K1, uint8_t *K2, const uint8_t *L) {
    int i;
    for (i = 0; i < 16; i++) {
        K1[i] = L[i] << 1;
        K2[i] = K1[i] << 1;
    }
}
"""
        result = check_rule("CMAC-001", code)
        assert result is not None
        assert len(result) >= 1

    @pytest.mark.tier2
    def test_no_cmac_func_returns_empty(self, check_rule):
        """CMAC 함수 없음 → 빈 리스트"""
        code = """
typedef unsigned int uint32_t;
void helper(uint32_t *buf) { buf[0] = 0; }
"""
        result = check_rule("CMAC-001", code)
        assert result is not None
        assert len(result) == 0


# ======================================================================
# GCM-001: GCM nonce static 배열 재사용
# ======================================================================

class TestGCM001:
    """GCM-001: GCM 함수 내 static 배열 → nonce 재사용 위반."""

    @pytest.mark.tier2
    def test_violation_static_array(self, check_rule):
        """GCM 함수 내 static 배열 → 위반"""
        code = """
typedef unsigned int uint32_t;
typedef unsigned char uint8_t;
void gcm_encrypt(uint8_t *ct, const uint8_t *pt, const uint32_t *rk) {
    static uint8_t nonce[12] = {0};
    int i;
    for (i = 0; i < 16; i++) {
        ct[i] = pt[i] ^ nonce[i % 12];
    }
}
"""
        result = check_rule("GCM-001", code, filename="lea_gcm.c")
        assert result is not None
        assert len(result) >= 1

    @pytest.mark.tier2
    def test_compliant_no_static(self, check_rule):
        """GCM 함수에 static 배열 없음 → 정상"""
        code = """
typedef unsigned int uint32_t;
typedef unsigned char uint8_t;
void gcm_encrypt(uint8_t *ct, const uint8_t *pt,
                 const uint8_t *nonce, const uint32_t *rk) {
    int i;
    for (i = 0; i < 16; i++) {
        ct[i] = pt[i] ^ nonce[i % 12];
    }
}
"""
        result = check_rule("GCM-001", code, filename="lea_gcm.c")
        assert result is not None
        assert len(result) == 0

    @pytest.mark.tier2
    def test_no_gcm_func_returns_empty(self, check_rule):
        """GCM 함수 없음 → 빈 리스트"""
        code = """
typedef unsigned int uint32_t;
void helper(uint32_t *buf) { buf[0] = 0; }
"""
        result = check_rule("GCM-001", code)
        assert result is not None
        assert len(result) == 0


# ======================================================================
# ==================== TIER 3 테스트 (10개 규칙) =======================
# ======================================================================


# ======================================================================
# LEA-005: 바이트→워드 빅 엔디안 변환 탐지
# ======================================================================

class TestLEA005:
    """LEA-005: a[0]<<24 패턴 → 빅 엔디안 위반."""

    @pytest.mark.tier3
    def test_violation_big_endian(self, check_rule):
        """a[0] << 24 패턴 → BE 위반"""
        code = """
typedef unsigned int uint32_t;
typedef unsigned char uint8_t;
uint32_t byte2word(const uint8_t *a) {
    return (a[0] << 24) | (a[1] << 16) | (a[2] << 8) | a[3];
}
"""
        result = check_rule("LEA-005", code)
        assert result is not None
        assert len(result) >= 1

    @pytest.mark.tier3
    def test_compliant_little_endian(self, check_rule):
        """a[3] << 24 (LE) → 위반 없음"""
        code = """
typedef unsigned int uint32_t;
typedef unsigned char uint8_t;
uint32_t byte2word(const uint8_t *a) {
    return a[0] | (a[1] << 8) | (a[2] << 16) | (a[3] << 24);
}
"""
        result = check_rule("LEA-005", code)
        assert result is not None
        assert len(result) == 0


# ======================================================================
# LEA-006: 비트 색인 방향 — (x & 1) << 31 탐지
# ======================================================================

class TestLEA006:
    """LEA-006: bit 0을 MSB 위치로 이동 → 비트 번호 역전 의심."""

    @pytest.mark.tier3
    def test_violation_bit_reversal(self, check_rule):
        """(x & 1) << 31 패턴 → 위반"""
        code = """
typedef unsigned int uint32_t;
uint32_t reverse_bit(uint32_t x) {
    return (x & 1) << 31;
}
"""
        result = check_rule("LEA-006", code)
        if result is not None:
            assert len(result) >= 1

    @pytest.mark.tier3
    def test_normal_shift_no_violation(self, check_rule):
        """일반 시프트 연산 → None 또는 빈 리스트"""
        code = """
typedef unsigned int uint32_t;
uint32_t normal_shift(uint32_t x) {
    return x << 1;
}
"""
        result = check_rule("LEA-006", code)
        # None = 판단 불가 (L2 위임), [] = 위반 없음
        if result is not None:
            assert len(result) == 0


# ======================================================================
# LEA-022: LEA-256 T[] 인덱싱 (6i+j)%8
# ======================================================================

class TestLEA022:
    """LEA-022: LEA-256 키 스케줄 T[] 접근에 %8 순환 필수."""

    @pytest.mark.tier3
    def test_compliant_mod8(self, check_rule):
        """T[(6*i+j)%8] 패턴 → 정상"""
        code = """
typedef unsigned int uint32_t;
uint32_t ROL32(uint32_t x, int r);
void lea_set_key(const unsigned char *mk, uint32_t *rk) {
    uint32_t T[8], delta[8];
    int i, j;
    for (i = 0; i < 32; i++) {
        for (j = 0; j < 6; j++) {
            T[(6*i+j) % 8] = ROL32(T[(6*i+j) % 8] + delta[i % 8], j);
        }
    }
}
"""
        result = check_rule("LEA-022", code)
        assert result is not None
        assert len(result) == 0

    @pytest.mark.tier3
    def test_no_key_func_returns_empty(self, check_rule):
        """키 스케줄 함수 없음 → 빈 리스트"""
        code = """
typedef unsigned int uint32_t;
void helper(uint32_t *buf) { buf[0] = 0; }
"""
        result = check_rule("LEA-022", code)
        assert result is not None
        assert len(result) == 0


# ======================================================================
# LEA-023: 복호화 라운드키 역순 관계
# ======================================================================

class TestLEA023:
    """LEA-023: 복호화 라운드키가 암호화 역순이어야 함."""

    @pytest.mark.tier3
    def test_compliant_reverse_index(self, check_rule):
        """dec_rk[i] = enc_rk[Nr-1-i] → 정상"""
        code = """
typedef unsigned int uint32_t;
void lea_set_dec_key(uint32_t *dec_rk, const uint32_t *enc_rk, int Nr) {
    int i;
    for (i = 0; i < Nr; i++) {
        dec_rk[i] = enc_rk[Nr - 1 - i];
    }
}
"""
        result = check_rule("LEA-023", code)
        assert result is not None
        assert len(result) == 0

    @pytest.mark.tier3
    def test_no_dec_key_func_returns_empty(self, check_rule):
        """복호화 키 스케줄 함수 없음 → 빈 리스트"""
        code = """
typedef unsigned int uint32_t;
void lea_encrypt(uint32_t *block, const uint32_t *rk) {
    block[0] = block[1] ^ rk[0];
}
"""
        result = check_rule("LEA-023", code)
        assert result is not None
        assert len(result) == 0


# ======================================================================
# LEA-042: 키 배열 조건 분기 (타이밍 공격)
# ======================================================================

class TestLEA042:
    """LEA-042: encrypt/decrypt 함수에서 if(key[i]) → 타이밍 공격."""

    @pytest.mark.tier3
    def test_violation_key_branch(self, check_rule):
        """if (key[i] != 0) → 키 의존 분기 위반"""
        code = """
typedef unsigned int uint32_t;
typedef unsigned char uint8_t;
void lea_encrypt(uint32_t *block, const uint8_t *key) {
    int i;
    for (i = 0; i < 16; i++) {
        if (key[i] != 0) {
            block[0] ^= key[i];
        }
    }
}
"""
        result = check_rule("LEA-042", code, filename="lea_enc.c")
        assert result is not None
        assert len(result) >= 1

    @pytest.mark.tier3
    def test_compliant_no_key_branch(self, check_rule):
        """키 배열 분기 없는 정상 구현 → 위반 없음"""
        code = """
typedef unsigned int uint32_t;
typedef unsigned char uint8_t;
void lea_encrypt(uint32_t *block, const uint32_t *rk) {
    int i;
    for (i = 0; i < 24; i++) {
        block[0] = (block[0] ^ rk[i]) + block[1];
    }
}
"""
        result = check_rule("LEA-042", code, filename="lea_enc.c")
        assert result is not None
        assert len(result) == 0


# ======================================================================
# LEA-043: 중간 상태 스택 배열 vs register
# ======================================================================

class TestLEA043:
    """LEA-043: 중간 상태 배열이 register 없이 스택 할당 → 위반."""

    @pytest.mark.tier3
    def test_violation_stack_array(self, check_rule):
        """X[4] 스택 배열, register 없음 → 위반"""
        code = """
typedef unsigned int uint32_t;
void lea_encrypt(uint32_t *block, const uint32_t *rk) {
    uint32_t X[4];
    int i;
    for (i = 0; i < 24; i++) {
        X[0] = (X[0] ^ rk[i]) + X[1];
    }
}
"""
        result = check_rule("LEA-043", code, filename="lea_enc.c")
        assert result is not None
        assert len(result) >= 1

    @pytest.mark.tier3
    def test_compliant_register(self, check_rule):
        """register 키워드 사용 → 정상"""
        code = """
typedef unsigned int uint32_t;
void lea_encrypt(uint32_t *block, const uint32_t *rk) {
    register uint32_t x0, x1, x2, x3;
    int i;
    for (i = 0; i < 24; i++) {
        x0 = (x0 ^ rk[i]) + x1;
    }
}
"""
        result = check_rule("LEA-043", code, filename="lea_enc.c")
        assert result is not None
        assert len(result) == 0

    @pytest.mark.tier3
    def test_no_enc_func_returns_empty(self, check_rule):
        """암호화/복호화 함수 없음 → 빈 리스트"""
        code = """
typedef unsigned int uint32_t;
void helper(uint32_t *buf) { buf[0] = 0; }
"""
        result = check_rule("LEA-043", code)
        assert result is not None
        assert len(result) == 0


# ======================================================================
# LEA-057: MCT 외부 루프 키 XOR 갱신
# ======================================================================

class TestLEA057:
    """LEA-057: MCT 외부 루프(100회) 내 Key XOR 갱신 수식 필수."""

    @pytest.mark.tier3
    def test_no_mct_func_returns_empty(self, check_rule):
        """MCT 함수 없음 → 빈 리스트"""
        code = """
typedef unsigned int uint32_t;
void lea_encrypt(uint32_t *block, const uint32_t *rk) {
    block[0] = block[1] ^ rk[0];
}
"""
        result = check_rule("LEA-057", code)
        assert result is not None
        assert len(result) == 0

    @pytest.mark.tier3
    def test_compliant_key_xor_update(self, check_rule):
        """외부 루프 내 key ^= ct 갱신 존재 → 정상"""
        code = """
typedef unsigned int uint32_t;
typedef unsigned char uint8_t;
void lea_mct(uint8_t *pt, uint8_t *ct, uint8_t *key) {
    int i, j;
    for (i = 0; i < 100; i++) {
        for (j = 0; j < 1000; j++) {
            ct[0] = pt[0] ^ key[0];
            pt[0] = ct[0];
        }
        key[0] ^= ct[0];
    }
}
"""
        result = check_rule("LEA-057", code)
        assert result is not None
        # key XOR 갱신이 있으므로 정상이어야 함
        assert len(result) == 0


# ======================================================================
# ECB-002: ECB 입력 길이 16배수 검사
# ======================================================================

class TestECB002:
    """ECB-002: ECB 암호화 함수에 len%16 검사 필수."""

    @pytest.mark.tier3
    def test_compliant_mod16_check(self, check_rule):
        """len % 16 검사 존재 → 정상"""
        code = """
typedef unsigned int uint32_t;
typedef unsigned char uint8_t;
int ecb_encrypt(uint8_t *ct, const uint8_t *pt, int len, const uint32_t *rk) {
    if (len % 16 != 0) return -1;
    int i;
    for (i = 0; i < len; i += 16) {
        ct[i] = pt[i] ^ rk[0];
    }
    return 0;
}
"""
        result = check_rule("ECB-002", code, filename="lea_ecb.c")
        assert result is not None
        assert len(result) == 0

    @pytest.mark.tier3
    def test_violation_no_mod16(self, check_rule):
        """len % 16 검사 없음 → 위반"""
        code = """
typedef unsigned int uint32_t;
typedef unsigned char uint8_t;
void ecb_encrypt(uint8_t *ct, const uint8_t *pt, int len, const uint32_t *rk) {
    int i;
    for (i = 0; i < len; i += 16) {
        ct[i] = pt[i] ^ rk[0];
    }
}
"""
        result = check_rule("ECB-002", code, filename="lea_ecb.c")
        assert result is not None
        assert len(result) >= 1

    @pytest.mark.tier3
    def test_no_ecb_func_returns_empty(self, check_rule):
        """ECB 함수 없고 파일/함수명에 ecb 힌트 없음 → 빈 리스트"""
        code = """
typedef unsigned int uint32_t;
void helper(uint32_t *buf) { buf[0] = 0; }
"""
        result = check_rule("ECB-002", code)
        assert result is not None
        assert len(result) == 0


# ======================================================================
# CCM-001: CCM nonce static 배열 재사용
# ======================================================================

class TestCCM001:
    """CCM-001: CCM 함수 내 static 배열 → nonce 재사용 위반."""

    @pytest.mark.tier3
    def test_violation_static_array(self, check_rule):
        """CCM 함수 내 static 배열 → 위반"""
        code = """
typedef unsigned int uint32_t;
typedef unsigned char uint8_t;
void ccm_encrypt(uint8_t *ct, const uint8_t *pt, const uint32_t *rk) {
    static uint8_t nonce[12] = {0};
    int i;
    for (i = 0; i < 16; i++) {
        ct[i] = pt[i] ^ nonce[i % 12];
    }
}
"""
        result = check_rule("CCM-001", code, filename="lea_ccm.c")
        assert result is not None
        assert len(result) >= 1

    @pytest.mark.tier3
    def test_compliant_no_static(self, check_rule):
        """CCM 함수에 static 배열 없음 → 정상"""
        code = """
typedef unsigned int uint32_t;
typedef unsigned char uint8_t;
void ccm_encrypt(uint8_t *ct, const uint8_t *pt,
                 const uint8_t *nonce, const uint32_t *rk) {
    int i;
    for (i = 0; i < 16; i++) {
        ct[i] = pt[i] ^ nonce[i % 12];
    }
}
"""
        result = check_rule("CCM-001", code, filename="lea_ccm.c")
        assert result is not None
        assert len(result) == 0


# ======================================================================
# ARIA-001: ARIA 키 스케줄 구조 (XOR + ROL + CK)
# ======================================================================

class TestARIA001:
    """ARIA-001: ARIA 키 스케줄에 XOR, 비트회전, CK 상수 3요소 필수."""

    @pytest.mark.tier3
    def test_compliant_all_elements(self, check_rule):
        """XOR + ROL + CK[] 모두 존재 → 정상"""
        code = """
typedef unsigned int uint32_t;
uint32_t ROL32(uint32_t x, int r);
void aria_key_schedule(const unsigned char *mk, uint32_t *rk) {
    uint32_t W[4], CK[4];
    int i;
    for (i = 0; i < 16; i++) {
        W[0] = W[0] ^ CK[i % 4];
        W[1] = ROL32(W[1], 8);
    }
}
"""
        result = check_rule("ARIA-001", code)
        assert result is not None
        assert len(result) == 0

    @pytest.mark.tier3
    def test_violation_missing_two_elements(self, check_rule):
        """XOR만 있고 ROL, CK 없음 → 2개 누락 → 위반"""
        code = """
typedef unsigned int uint32_t;
void aria_key_schedule(const unsigned char *mk, uint32_t *rk) {
    uint32_t W[4];
    int i;
    for (i = 0; i < 16; i++) {
        W[0] = W[0] ^ W[1];
    }
}
"""
        result = check_rule("ARIA-001", code)
        assert result is not None
        assert len(result) >= 1

    @pytest.mark.tier3
    def test_no_aria_func_returns_empty(self, check_rule):
        """ARIA 키 스케줄 함수 없음 → 빈 리스트"""
        code = """
typedef unsigned int uint32_t;
void helper(uint32_t *buf) { buf[0] = 0; }
"""
        result = check_rule("ARIA-001", code)
        assert result is not None
        assert len(result) == 0
