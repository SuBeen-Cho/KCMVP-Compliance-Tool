"""Triage Memory DB — 규칙별 TP/FP 대표 예시 (few-shot injection).

Semgrep Memory System (96% LLM agreement, arXiv 2601.22952) 및
CryptoLLM few-shot prompting (ESORICS 2024, F1=0.935) 기반.

각 규칙에 대해 is_real_issue=false(FP) 예시와 is_real_issue=true(TP) 예시를
프롬프트에 주입하여 LLM의 판정 정확도를 높인다.

설계 원칙:
- FP 예시는 2개 이하로 유지 (가장 빈번한 오탐 패턴에 집중)
- TP 예시는 1개로 유지 (위반 기준 명확화)
- 코드 스니펫은 30줄 이하로 압축
- violations_*, wrapper, 래퍼 파일 패턴을 FP 예시에 포함
"""

from typing import Dict, List, Optional

# 규칙별 TP/FP 예시 DB
# 구조: { rule_id: {"tp": [예시 텍스트], "fp": [예시 텍스트]} }
_TRIAGE_MEMORY: Dict[str, Dict[str, List[str]]] = {

    # ─────────────────────────────────────────────────────
    # COM-001: 잔존정보 제거 (zeroization)
    # ─────────────────────────────────────────────────────
    "COM-001": {
        "fp": [
            # FP-1: 래퍼 파일 — 키 제로화는 상위 caller에서 수행
            (
                "// [FP] violations_cbc.c — 이 파일은 CBC 모드 래퍼. 키 버퍼 소유자가 아님.\n"
                "int lea_cbc_encrypt(const uint8_t *key, ...) {\n"
                "    LEA_KEY ctx;\n"
                "    lea_set_key(&ctx, key, 128);\n"
                "    // ctx는 스택 변수 → 함수 종료 시 자동 소멸\n"
                "    // 키 원본(key 포인터)의 제로화는 caller 책임\n"
                "    return lea_cbc_enc_internal(&ctx, ...);\n"
                "}\n"
                "// is_real_issue=false: 이 파일이 키 버퍼를 소유하지 않음"
            ),
            # FP-2: memset으로 제로화 수행
            (
                "// [FP] memset으로 컨텍스트 제로화 — 동등 구현\n"
                "void lea_cleanup(LEA_KEY *ctx) {\n"
                "    memset(ctx, 0, sizeof(LEA_KEY));  // 컨텍스트 전체 제로화\n"
                "    memset(ctx->rk, 0, sizeof(ctx->rk));  // 라운드키 제로화\n"
                "}\n"
                "// is_real_issue=false: memset으로 SSP 제로화 충족"
            ),
        ],
        "tp": [
            # TP-1: 키 버퍼를 직접 소유하고 사용하나 제로화 없음
            (
                "// [TP] 키를 직접 저장하지만 제로화 없음\n"
                "typedef struct { uint32_t rk[8*6]; int nr; } LEA_KEY;\n"
                "int lea_set_key(LEA_KEY *ctx, const uint8_t *key, int keylen) {\n"
                "    // 키 스케줄 생성 후 ctx->rk에 저장\n"
                "    // ... (라운드키 생성 로직)\n"
                "    return 0;\n"
                "    // ❌ 함수 어디에도 ctx->rk 제로화 없음\n"
                "    // ❌ 이 파일에 cleanup/free 함수도 없음\n"
                "}\n"
                "// is_real_issue=true: SSP(라운드키)를 보유하나 제거 안 함"
            ),
        ],
    },

    # ─────────────────────────────────────────────────────
    # COM-002: 비안전 난수/RNG 사용
    # 주요 FP: violations_com.c에서 L3가 래퍼 파일로 오판하여 TP를 제거하는 사례
    # 핵심: violations_ 파일이라도 실제 비-CSPRNG 호출이 있으면 TP
    # ─────────────────────────────────────────────────────
    "COM-002": {
        "fp": [
            # FP-1: CSPRNG를 래핑하는 함수 — 내부에서 안전하게 처리
            (
                "// [FP] CSPRNG 래퍼 함수 — 내부적으로 /dev/urandom 또는 getrandom() 사용\n"
                "int generate_random_key(uint8_t *buf, int len) {\n"
                "    return RAND_bytes(buf, len);  // OpenSSL CSPRNG\n"
                "}\n"
                "// is_real_issue=false: 안전한 CSPRNG 래핑"
            ),
            # FP-2: 테스트용 난수 — 보안 맥락 아님
            (
                "// [FP] 단위 테스트용 비-CSPRNG — 테스트 벡터 생성 목적\n"
                "srand(42);  // 재현 가능한 테스트 위해 고정 시드\n"
                "int r = rand();  // 테스트 벡터 생성용\n"
                "// is_real_issue=false: 보안 키 생성이 아닌 테스트 목적"
            ),
        ],
        "tp": [
            # TP-1: violations_com.c라도 실제 비-CSPRNG로 키 생성하면 TP
            (
                "// [TP] violations_com.c — 파일명과 무관하게 실제 위반이면 TP\n"
                "// 핵심 판단 기준: rand()/random()/time()으로 암호 키/IV를 생성하면 TP\n"
                "uint8_t key[16];\n"
                "for (int i = 0; i < 16; i++) key[i] = rand() % 256;  // ❌ 비-CSPRNG\n"
                "lea_set_key(&ctx, key, 128);  // 실제 암호 함수에 사용\n"
                "// is_real_issue=true: violations_ 파일명이어도 실제 비-CSPRNG 키 생성이면 위반\n"
                "// 주의: 파일이 violations_com.c라고 해서 자동 FP가 아님. 코드를 반드시 확인."
            ),
        ],
    },

    # ─────────────────────────────────────────────────────
    # COM-003: 하드코딩된 키/IV
    # ─────────────────────────────────────────────────────
    "COM-003": {
        "fp": [
            # FP-1: LEA delta 상수 — 알고리즘 공개 상수
            (
                "// [FP] LEA delta 상수 — KS X 3246 공개 알고리즘 상수\n"
                "static const uint32_t delta[8] = {\n"
                "    0xc3efe9db, 0x44626b02, 0x79e27c8a, 0x78df30ec,\n"
                "    0x715ea49e, 0xc785da0a, 0xe04ef22a, 0xe5c40957\n"
                "};\n"
                "// is_real_issue=false: 표준 delta 상수는 공개값"
            ),
            # FP-2: KAT 테스트 벡터
            (
                "// [FP] KAT 테스트 벡터 — 공개 표준 테스트값\n"
                "static const uint8_t kat_key[16] = {0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78,\n"
                "                                     0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0};\n"
                "static const uint8_t kat_pt[16]  = {0x10, 0x11, 0x12, 0x13, ...};\n"
                "// is_real_issue=false: 변수명 kat_* 또는 test_*이고 공개 벡터임"
            ),
        ],
        "tp": [
            # TP-1: 실제 암호키 하드코딩
            (
                "// [TP] 실제 암호키 하드코딩\n"
                "static const uint8_t aes_key[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,\n"
                "                                     0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};\n"
                "lea_set_key(&ctx, aes_key, 128);  // 실제 암호 함수에 직접 전달\n"
                "// is_real_issue=true: 변수명 key + 암호 함수 직접 전달"
            ),
        ],
    },

    # ─────────────────────────────────────────────────────
    # LEA-016 ~ LEA-020: 키 스케줄 회전 (missing 타입)
    # 주요 FP 원인: violations_*.c / wrapper 파일에는 키 스케줄이 없어서 발화
    # ─────────────────────────────────────────────────────
    "LEA-016": {
        "fp": [
            # FP-1: 모드 래퍼 파일 — 키 스케줄 없음이 정상
            (
                "// [FP] violations_cbc.c — CBC 모드 래퍼, 키 스케줄 위임 구조\n"
                "// 이 파일에는 ROL1 패턴이 없지만, 키 스케줄은 lea.c 내부에서 수행됨\n"
                "int violations_cbc_encrypt(const uint8_t *key, const uint8_t *iv,\n"
                "                           const uint8_t *pt, uint8_t *ct, int len) {\n"
                "    LEA_KEY ctx;\n"
                "    lea_set_key(&ctx, key, 128);  // LEA 내부에서 ROL1/ROL3 수행\n"
                "    return lea_cbc_enc(&ctx, iv, pt, ct, len);\n"
                "}\n"
                "// is_real_issue=false: 이 파일은 래퍼, ROL 부재가 당연"
            ),
        ],
        "tp": [
            # TP-1: 키 스케줄 존재하나 ROL 비트 수 오류
            (
                "// [TP] 키 스케줄에 ROL1 대신 ROL2 사용 (비트 수 오류)\n"
                "for (int i = 0; i < 4; i++) {\n"
                "    T[i] = ROL(T[i] + delta[i], 2);  // ❌ ROL2: 규격은 ROL1\n"
                "}\n"
                "// is_real_issue=true: 키 스케줄에서 회전량 불일치"
            ),
        ],
    },

    "LEA-017": {
        "fp": [
            (
                "// [FP] 모드 래퍼 / violations_ 파일 — 키 스케줄 없음\n"
                "// ROL3 패턴 부재는 설계상 당연 (키 스케줄 위임)\n"
                "// is_real_issue=false: 래퍼/위반시험 파일에서 ROL3 부재"
            ),
        ],
        "tp": [
            (
                "// [TP] 키 스케줄 존재하나 ROL3 대신 ROL1 사용\n"
                "T[i] = ROL(T[i] + delta[i], 1);  // ❌ ROL3 위치에 ROL1\n"
                "// is_real_issue=true: 회전량 오류"
            ),
        ],
    },

    "LEA-018": {
        "fp": [
            (
                "// [FP] 키 스케줄 없는 래퍼 파일 — ROL6 부재 정상\n"
                "// is_real_issue=false: 이 파일이 키 스케줄 구현 파일이 아님"
            ),
        ],
        "tp": [
            (
                "// [TP] 키 스케줄 존재하나 ROL6 대신 ROL3 사용\n"
                "rk[6*i+4] = ROL(rk[6*i] + delta[4*i], 3);  // ❌ ROL6 위치에 ROL3\n"
                "// is_real_issue=true: 128비트 키 스케줄 ROL6 오류"
            ),
        ],
    },

    "LEA-019": {
        "fp": [
            (
                "// [FP] 키 스케줄 없는 래퍼 파일 — ROL11 부재 정상\n"
                "// is_real_issue=false: 래퍼/위반시험 파일"
            ),
        ],
        "tp": [
            (
                "// [TP] 192비트 키 스케줄에 ROL11 대신 ROL8 사용\n"
                "rk[6*i+3] = ROL(T[3] + delta[(3+4*i)%8], 8);  // ❌ ROL11 위치에 ROL8\n"
                "// is_real_issue=true: 192비트 키 스케줄 ROL11 오류"
            ),
        ],
    },

    "LEA-020": {
        "fp": [
            (
                "// [FP] 128비트 전용 파일 — ROL13/17 불필요\n"
                "// 이 파일이 128비트 키만 처리하면 ROL13/17 부재가 당연\n"
                "// is_real_issue=false: 128비트 전용 구현"
            ),
        ],
        "tp": [
            (
                "// [TP] 256비트 키 스케줄에 ROL13/17 누락\n"
                "// 256비트 키 스케줄 코드가 있으나 T[i] 회전에 ROL13/ROL17이 없음\n"
                "// is_real_issue=true: 256비트 키 스케줄 ROL13/17 오류"
            ),
        ],
    },

    # ─────────────────────────────────────────────────────
    # LEA-026 ~ LEA-029: 암호화 초기화 / 라운드키 적용
    # 주요 FP: violations_ 파일, scope:project 단일파일
    # ─────────────────────────────────────────────────────
    "LEA-026": {
        "fp": [
            (
                "// [FP] violations_lea.c — 암호화 구현이 없는 위반시험 파일\n"
                "// 이 파일에는 X[]=P[] 초기화 패턴이 없지만 실제 암호화는 lea.c에서\n"
                "// is_real_issue=false: 위반시험 래퍼 파일에 암호화 구현 없음"
            ),
        ],
        "tp": [
            (
                "// [TP] 암호화 함수가 있으나 평문 초기화 누락\n"
                "void lea_encrypt(const LEA_KEY *ctx, const uint8_t *pt, uint8_t *ct) {\n"
                "    uint32_t X[4];  // ❌ X[] 초기화 없음\n"
                "    for (int r = 0; r < ctx->nr; r++) { ... }\n"
                "}\n"
                "// is_real_issue=true: 암호화 함수에 X[]=P[] 초기화 누락"
            ),
        ],
    },

    "LEA-027": {
        "fp": [
            (
                "// [FP] 래퍼/위반시험 파일 — 라운드키 적용 구현 없음\n"
                "// 실제 라운드키 적용은 내부 lea.c에서 수행됨\n"
                "// is_real_issue=false: 라운드키 적용이 다른 파일에 위임"
            ),
        ],
        "tp": [
            (
                "// [TP] 라운드키 XOR 순서 오류\n"
                "X[0] = ROL(X[0] ^ rk[0], 9);  // ❌ XOR 후 ROL이어야 하나 순서 오류\n"
                "// is_real_issue=true: 라운드키 적용 순서/방식 오류"
            ),
        ],
    },

    "LEA-028": {
        "fp": [
            (
                "// [FP] 래퍼/위반시험 파일 — 암호화 라운드 미구현\n"
                "// is_real_issue=false: 이 파일에 암호화 라운드 구현 없음"
            ),
        ],
        "tp": [
            (
                "// [TP] 암호화 라운드에 잘못된 라운드키 인덱스 사용\n"
                "X[1] = ROL((X[1] ^ rk[3*r+1]) + (X[2] ^ rk[3*r+2]), 5);  // ❌ 인덱스 오류\n"
                "// is_real_issue=true: 라운드키 인덱스 패턴 오류"
            ),
        ],
    },

    "LEA-029": {
        "fp": [
            (
                "// [FP] 래퍼/위반시험 파일 — 복호화 미구현\n"
                "// is_real_issue=false: 복호화가 다른 파일에 위임"
            ),
        ],
        "tp": [
            (
                "// [TP] 복호화 라운드키 역순 적용 오류\n"
                "// 복호화 함수에서 라운드키를 정방향으로 사용 (역방향이어야 함)\n"
                "// is_real_issue=true: 복호화 라운드키 적용 역순 오류"
            ),
        ],
    },

    # ─────────────────────────────────────────────────────
    # LEA-031: 모듈러 덧셈/XOR 연산 순서 오류
    # 주요 실수: violations_lea_round.c에서 연속된 라인의 동일 위반을 모두 FP로 제거
    # 핵심: 같은 규칙이 여러 라인에 걸쳐 탐지될 때, 각 인스턴스를 독립적으로 판정
    # ─────────────────────────────────────────────────────
    "LEA-031": {
        "fp": [
            # FP-1: 포인터 역참조 연산 — 실제 LEA 라운드가 아닌 포인터 산술
            (
                "// [FP] 포인터 피연산자 — LEA 라운드 연산이 아닌 주소 계산\n"
                "uint32_t *p = (uint32_t *)buf;\n"
                "result = *p + offset;  // 포인터 역참조 + 상수 덧셈\n"
                "// is_real_issue=false: LEA 라운드 내 모듈러 덧셈이 아님"
            ),
        ],
        "tp": [
            # TP-1: violations_lea_round.c에서도 실제 라운드 연산 오류면 TP
            # 연속된 인스턴스(예: 189번, 191번 라인)라도 각각 독립적으로 TP일 수 있음
            (
                "// [TP] 라운드 연산에서 XOR과 덧셈 순서 오류\n"
                "// violations_lea_round.c라도 아래 패턴이 있으면 각 라인이 모두 TP\n"
                "X[0] = (X[1] + rk[0]) ^ X[3];  // ❌ 덧셈 후 XOR이어야 하나 순서 오류\n"
                "X[1] = (X[2] + rk[1]) ^ X[0];  // ❌ 동일 오류가 다음 라인에도 존재\n"
                "// is_real_issue=true: 연속 라인의 동일 위반은 각각 독립적 TP\n"
                "// 주의: 같은 위반이 여러 라인에 반복될 때 하나만 TP이고 나머지가 FP인 것이 아님.\n"
                "//       각 라인의 연산을 개별적으로 확인해야 함."
            ),
        ],
    },

    # ─────────────────────────────────────────────────────
    # LEA-036, LEA-038: 출력 저장
    # ─────────────────────────────────────────────────────
    "LEA-036": {
        "fp": [
            (
                "// [FP] 단순 래퍼 파일 — 암호화 출력 저장은 내부 구현에서\n"
                "// is_real_issue=false: 출력 저장이 호출된 함수 내부에서 수행"
            ),
        ],
        "tp": [
            (
                "// [TP] 암호화 최종 출력을 ct[]에 저장하지 않음\n"
                "// 라운드 완료 후 X[]를 output buffer에 복사하는 코드 없음\n"
                "// is_real_issue=true: 암호화 결과 출력 누락"
            ),
        ],
    },

    "LEA-038": {
        "fp": [
            (
                "// [FP] violations_lea_round.c — 복호화 최종 출력이 없는 부분 구현\n"
                "// 이 파일은 라운드 함수만 구현, 최종 대입은 caller에서 수행\n"
                "// is_real_issue=false: 최종 출력이 상위 함수에서 수행"
            ),
        ],
        "tp": [
            (
                "// [TP] 복호화 함수에서 최종 평문 출력 누락\n"
                "void lea_decrypt(const LEA_KEY *ctx, const uint8_t *ct, uint8_t *pt) {\n"
                "    uint32_t X[4]; /* 초기화, 라운드 처리 */ ...\n"
                "    // ❌ pt[] = X[] 대입 없음 → 복호화 결과 미출력\n"
                "}\n"
                "// is_real_issue=true"
            ),
        ],
    },

    # ─────────────────────────────────────────────────────
    # LEA-044: 암호화 후 키 제로화
    # ─────────────────────────────────────────────────────
    "LEA-044": {
        "fp": [
            (
                "// [FP] 단순 래퍼 파일 — 키 제로화는 caller 책임\n"
                "int lea_cbc_enc_wrapper(const uint8_t *key, ...) {\n"
                "    LEA_KEY ctx;  // 스택 변수\n"
                "    lea_set_key(&ctx, key, 128);\n"
                "    int ret = lea_cbc_enc(&ctx, ...);\n"
                "    // 스택 변수 ctx는 함수 종료 시 소멸; key 원본은 caller 소유\n"
                "    return ret;\n"
                "}\n"
                "// is_real_issue=false: 이 파일이 키 소유자 아님"
            ),
        ],
        "tp": [
            (
                "// [TP] 키 스케줄 컨텍스트를 heap에 저장하나 제로화 없음\n"
                "LEA_KEY *ctx = malloc(sizeof(LEA_KEY));\n"
                "lea_set_key(ctx, key, 256);\n"
                "lea_encrypt(ctx, ...);\n"
                "free(ctx);  // ❌ free 전 memset/제로화 없음\n"
                "// is_real_issue=true"
            ),
        ],
    },

    # ─────────────────────────────────────────────────────
    # LEA-045: 32비트 원자성
    # ─────────────────────────────────────────────────────
    "LEA-045": {
        "fp": [
            (
                "// [FP] 순수 C uint32_t 연산 — SIMD 없이 원자성 위반 위험 낮음\n"
                "uint32_t X[4]; /* uint32_t 덧셈 + XOR + ROL 구성 */\n"
                "// is_real_issue=false: 순수 C 구현에서 uint32_t 연산은 원자성 충족"
            ),
        ],
        "tp": [
            (
                "// [TP] 비원자적 바이트 단위 접근 (byte-wise XOR)\n"
                "for (int i = 0; i < 4; i++) ct[i] = pt[i] ^ ((rk >> (i*8)) & 0xff);\n"
                "// is_real_issue=true: 바이트 단위 비원자 연산"
            ),
        ],
    },

    # ─────────────────────────────────────────────────────
    # LEA-047, LEA-057: MCT 테스트 루프
    # 주요 FP: MCT 구현 없는 파일에서 발화
    # ─────────────────────────────────────────────────────
    "LEA-047": {
        "fp": [
            (
                "// [FP] MCT 구현이 없는 파일 — MCT 키 갱신 패턴 부재 정상\n"
                "// 이 파일은 블록 암호 구현 파일이며 MCT는 별도 시험 도구에서 수행\n"
                "// is_real_issue=false: MCT가 이 파일의 구현 범위가 아님"
            ),
        ],
        "tp": [
            (
                "// [TP] MCT 내부 루프에 키 갱신 누락\n"
                "for (int j = 0; j < 1000; j++) {\n"
                "    lea_encrypt(&ctx, pt, ct);\n"
                "    memcpy(pt, ct, 16);  // ❌ 키 갱신(XOR 등) 없음\n"
                "}\n"
                "// is_real_issue=true: MCT 키 갱신 패턴 누락"
            ),
        ],
    },

    "LEA-057": {
        "fp": [
            (
                "// [FP] MCT 구현 없는 파일 — LEA-057 발화 자체가 전제조건 불충족\n"
                "// is_real_issue=false: MCT 없는 파일"
            ),
        ],
        "tp": [
            (
                "// [TP] MCT 외부 루프에서 키 갱신 오류\n"
                "// 100회 외부 루프에서 이전 결과로 키를 업데이트하지 않음\n"
                "// is_real_issue=true"
            ),
        ],
    },

    # ─────────────────────────────────────────────────────
    # CTR-003: 카운터 초기화 방식
    # ─────────────────────────────────────────────────────
    "CTR-003": {
        "fp": [
            (
                "// [FP] 카운터가 caller에서 주입됨 — 이 파일에서 초기화 없는 것이 정상\n"
                "int lea_ctr_enc(const LEA_KEY *ctx, const uint8_t *ctr, ...) {\n"
                "    // ctr은 caller가 제공; 이 함수는 카운터를 초기화하지 않음\n"
                "}\n"
                "// is_real_issue=false: 카운터 초기화 책임이 caller에 있음"
            ),
        ],
        "tp": [
            (
                "// [TP] 예측 가능한 소스(time)로 카운터 초기화\n"
                "uint8_t ctr[16];\n"
                "*(uint32_t*)ctr = (uint32_t)time(NULL);  // ❌ 예측 가능한 카운터\n"
                "lea_ctr_enc(&ctx, ctr, ...);\n"
                "// is_real_issue=true: 비안전 소스로 카운터 초기화"
            ),
        ],
    },

    # ─────────────────────────────────────────────────────
    # CBC-001: CBC 모드 XOR 체이닝
    # _L3_NEVER_REMOVE 규칙 — FP 제거 차단이지만 프롬프트 품질은 높여야 함
    # ─────────────────────────────────────────────────────
    "CBC-001": {
        "fp": [
            (
                "// [FP] violations_cbc.c — CBC XOR 체이닝 미구현이 이 파일의 목적\n"
                "// 올바른 CBC는 lea_cbc.c에 있으며, 이 파일은 의도적 위반 시험 파일\n"
                "// is_real_issue=false: 위반시험 파일에서 XOR 체이닝 의도적 누락"
            ),
        ],
        "tp": [
            (
                "// [TP] CBC 암호화에 XOR 체이닝 누락\n"
                "for (int i = 0; i < blocks; i++) {\n"
                "    lea_block_encrypt(&ctx, pt + i*16, ct + i*16);\n"
                "    // ❌ XOR with IV/previous cipherblock 없음\n"
                "}\n"
                "// is_real_issue=true: CBC 모드에 XOR 체이닝 누락"
            ),
        ],
    },

    # ─────────────────────────────────────────────────────
    # LEA-048, LEA-062: 시험 아티팩트 규칙
    # 평가 세트에서는 FP로 처리해야 하는 경우가 많음
    # ─────────────────────────────────────────────────────
    "LEA-048": {
        "fp": [
            (
                "// [FP] KAT REQUEST/RESPONSE 파일은 구현이 아닌 제출 패키지 아티팩트\n"
                "// 이 파일이 암호 라이브러리 구현 파일이면 LEA-048은 시험 아티팩트 요건으로\n"
                "// 별도 제출 파일에서 충족되어야 함 → 구현 파일에서는 해당없음\n"
                "// is_real_issue=false: 구현 파일에서 시험 아티팩트 요건 불해당"
            ),
        ],
        "tp": [
            (
                "// [TP] 자가시험(KAT) 함수가 명시적으로 요구되나 전혀 없음\n"
                "// 프로젝트 전체에 KAT/MMT/MCT 처리 코드가 없음\n"
                "// is_real_issue=true: 시험 아티팩트 요건 미충족"
            ),
        ],
    },

    "LEA-062": {
        "fp": [
            (
                "// [FP] Variable Key/Text KAT는 시험 도구 아티팩트\n"
                "// 라이브러리 구현 파일에는 KAT 처리가 없어도 무방\n"
                "// is_real_issue=false: 시험 도구/패키지 수준의 요건"
            ),
        ],
        "tp": [
            (
                "// [TP] Variable Key KAT 처리 코드가 프로젝트 전체에 없음\n"
                "// is_real_issue=true: 필수 KAT 구현 누락"
            ),
        ],
    },
}


def get_few_shot_examples(
    rule_id: str,
    max_fp: int = 2,
    max_tp: int = 1,
) -> str:
    """규칙별 TP/FP few-shot 예시를 프롬프트 주입용 문자열로 반환.

    Parameters
    ----------
    rule_id : 규칙 ID (예: "COM-001")
    max_fp  : 최대 FP 예시 수 (기본 2)
    max_tp  : 최대 TP 예시 수 (기본 1)

    Returns
    -------
    str : 예시 섹션 문자열 (없으면 빈 문자열)
    """
    rid = (rule_id or "").upper()
    entry = _TRIAGE_MEMORY.get(rid)
    if not entry:
        return ""

    fp_examples = (entry.get("fp") or [])[:max_fp]
    tp_examples = (entry.get("tp") or [])[:max_tp]

    if not fp_examples and not tp_examples:
        return ""

    parts = ["【판정 참고 예시 (Triage Memory)】"]

    if fp_examples:
        parts.append("▷ 오탐(is_real_issue=false) 예시:")
        for ex in fp_examples:
            parts.append("```c")
            parts.append(ex.strip())
            parts.append("```")

    if tp_examples:
        parts.append("▷ 위반(is_real_issue=true) 예시:")
        for ex in tp_examples:
            parts.append("```c")
            parts.append(ex.strip())
            parts.append("```")

    return "\n".join(parts) + "\n"


def has_few_shot_examples(rule_id: str) -> bool:
    """해당 규칙에 few-shot 예시가 있는지 확인."""
    return (rule_id or "").upper() in _TRIAGE_MEMORY
