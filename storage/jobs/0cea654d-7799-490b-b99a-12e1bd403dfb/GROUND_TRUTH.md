# Accuracy Test v5 — Ground Truth (54건)
# v4(48건) + AST 구조 체커 확장(6건)
# Format: file | label | expected_rule_id | description

## violations_gcm_ext.c (P = 위반, 7건)
violations_gcm_ext.c | P | GCM-002 | P01: tag_len=3 (4 미만)
violations_gcm_ext.c | P | GCM-002 | P02: tag_len=20 (16 초과)
violations_gcm_ext.c | P | GCM-003 | P03: set_ctr 먼저 호출 후 init (순서 위반)
violations_gcm_ext.c | P | GCM-004 | P04: 인증 실패 시 0 반환 (−1 미반환)
violations_gcm_ext.c | P | GCM-005 | P05: nonce/key 제로화 누락
violations_gcm_ext.c | P | GCM-004 | P06: tag_mismatch 처리 누락
violations_gcm_ext.c | P | GCM-002 | P07: t_len=2 (4 미만)

## violations_cbc_ext.c (P = 위반, 6건)
violations_cbc_ext.c | P | CBC-003 | P08: rand()로 IV 생성 (CSPRNG 미사용)
violations_cbc_ext.c | P | CBC-004 | P09: IV/키 사용 후 제로화 누락
violations_cbc_ext.c | P | CBC-005 | P10: printf로 padding 오류 상세 노출
violations_cbc_ext.c | P | CBC-061 | P11: iv[8] — 8바이트 IV (16 필요)
violations_cbc_ext.c | P | CBC-061 | P12: iv[32] — 32바이트 IV (16 필요)
violations_cbc_ext.c | P | CBC-005 | P13: return -INVALID_PADDING 상수 노출

## violations_ctr_ext.c (P = 위반, 9건)
violations_ctr_ext.c | P | CTR-003 | P14: rand()로 nonce 생성 (CSPRNG 미사용)
violations_ctr_ext.c | P | CTR-004 | P15: 카운터/키 제로화 누락
violations_ctr_ext.c | P | CTR-LEA-001 | P16: ctr[8] — 8바이트 카운터 (16 필요)
violations_ctr_ext.c | P | CCM-002 | P17: Nlen=6 (7 미만)
violations_ctr_ext.c | P | CCM-002 | P18: nonce_len=14 (13 초과)
violations_ctr_ext.c | P | CCM-003 | P19: Tlen=5 (허용값 아님)
violations_ctr_ext.c | P | CCM-003 | P20: t_len=2 (4 미만)
violations_ctr_ext.c | P | CCM-004 | P21: 인증 실패 시 평문 미폐기
violations_ctr_ext.c | P | OFB-001 | P22: iv[8] — 8바이트 IV (16 필요)

## violations_misc_ext.c (P = 위반, 6건)
violations_misc_ext.c | P | CFB-001 | P23: rand()로 CFB IV 생성
violations_misc_ext.c | P | CMAC-002 | P24: memcmp으로 태그 비교 (타이밍 취약)
violations_misc_ext.c | P | CMAC-003 | P25: K1/K2 사용 후 제로화 누락
violations_misc_ext.c | P | COM-002 | P26: lea_set_key/lea_cbc_encrypt 반환값 무시
violations_misc_ext.c | P | LEA-041 | P27: sbox[] 배열 사용 (ARX 원칙 위반)
violations_misc_ext.c | P | CMAC-002 | P28: strcmp로 MAC 비교 (타이밍 취약)

## violations_cbc_struct.c (P = 위반, 3건) — AST 구조 체커
violations_cbc_struct.c | P | CBC-001 | P29: CBC 암호화에서 XOR(^) 연쇄 없음
violations_cbc_struct.c | P | CBC-002 | P30: CBC 복호화에서 XOR(^) 연쇄 없음
violations_cbc_struct.c | P | ECB-002 | P31: ECB 암호화 len%16 검사 없음

## safe_code_v4.c (N = 정상 코드, 20건)
safe_code_v4.c | N | GCM-002 | N01: tag_len=16 정상
safe_code_v4.c | N | GCM-002 | N02: t_len=12 정상
safe_code_v4.c | N | GCM-004 | N03: 인증 실패 시 -1 반환 정상
safe_code_v4.c | N | GCM-005 | N04: explicit_bzero로 올바른 제로화
safe_code_v4.c | N | CBC-061 | N05: iv[16] 정상 크기
safe_code_v4.c | N | CBC-005 | N06: return -1만 반환 (정보 미노출)
safe_code_v4.c | N | CTR-LEA-001 | N07: ctr[16] 정상 크기
safe_code_v4.c | N | CCM-002 | N08: Nlen=8 정상 (7~13 범위)
safe_code_v4.c | N | CCM-003 | N09: Tlen=8 정상 ({4,6,8,...,16} 중 하나)
safe_code_v4.c | N | CCM-004 | N10: memset(pt,0,len) 인증 실패 시 처리
safe_code_v4.c | N | OFB-001 | N11: iv[16] 정상 크기
safe_code_v4.c | N | CMAC-002 | N12: crypto_memcmp 상수 시간 비교
safe_code_v4.c | N | CMAC-003 | N13: K1/K2 explicit_bzero 올바른 제로화
safe_code_v4.c | N | COM-002 | N14: 모든 반환값 검사 (ret < 0 체크)
safe_code_v4.c | N | LEA-041 | N15: ARX 연산만 사용 (S-box 없음)
safe_code_v4.c | N | CBC-003 | N16: getrandom으로 IV 생성
safe_code_v4.c | N | CTR-003 | N17: getrandom으로 nonce 생성
safe_code_v4.c | N | CCM-002 | N18: nonce_len=13 정상 (최대)
safe_code_v4.c | N | GCM-003 | N19: init→set_ctr→encrypt→final 올바른 순서
safe_code_v4.c | N | CFB-001 | N20: getrandom으로 CFB IV 생성

## safe_code_v5.c (N = 정상 코드, 3건) — AST 구조 정상
safe_code_v5.c | N | CBC-001 | N21: CBC 암호화에서 XOR 연쇄 있음 (정상)
safe_code_v5.c | N | CBC-002 | N22: CBC 복호화에서 XOR 연쇄 있음 (정상)
safe_code_v5.c | N | ECB-002 | N23: ECB len%16 검사 있음 (정상)
violations_gcm_nonce.c | P | GCM-001 | static nonce → GCM nonce 재사용 위반
violations_ccm_nonce.c | P | CCM-001 | static nonce → CCM nonce 재사용 위반
violations_lea_timing.c | P | LEA-042 | key[i]!=0 조건 분기 → 타이밍 공격 취약
violations_lea_mct.c | P | LEA-046 | MCT 루프 10x100 → 100x1000 이어야 함
safe_gcm_v6.c | N | GCM-001 | stack nonce → 재사용 없음
safe_ccm_v6.c | N | CCM-001 | stack nonce → 재사용 없음
safe_lea_timing_v6.c | N | LEA-042 | XOR only → 상수 시간 연산
safe_lea_mct_v6.c | N | LEA-046 | 100x1000 루프 → 정상 MCT 구조
violations_ctr_static.c | P | CTR-002 | static counter → CTR nonce 재사용 위반
violations_cmac_nokey.c | P | CMAC-001 | 0x87 XOR 서브키 파생 없음
violations_com003_key.c | P | COM-003 | 변수명 key + 8+hex 리터럴 하드코딩 키
safe_ctr_v7.c | N | CTR-002 | stack counter → 재사용 없음
safe_cmac_v7.c | N | CMAC-001 | 올바른 0x87 XOR 서브키 파생
safe_com003_sbox.c | N | COM-003 | S-box 상수 → 오탐이면 안 됨
safe_com003_delta.c | N | COM-003 | LEA delta 상수 → 오탐이면 안 됨
safe_com003_testvec.c | N | COM-003 | 테스트벡터 배열 → 오탐이면 안 됨
violations_lea047_ecb.c | P | LEA-047 | ECB-MCT PT←CT 갱신 없음
violations_lea047_cbc.c | P | LEA-047 | CBC-MCT IV 갱신 없음
safe_ccm_v6.c | N | LEA-047 | CCMCtx 포함이지만 MCT 함수 없음
safe_gcm_v6.c | N | LEA-047 | GCMCtx 포함이지만 MCT 함수 없음
safe_lea_mct_v6.c | N | LEA-047 | 올바른 MCT 루프 구조
safe_lea047_ecb.c | N | LEA-047 | ECB-MCT PT←CT 갱신 있음
safe_lea047_cbc.c | N | LEA-047 | CBC-MCT IV 갱신 있음
safe_lea047_ctr.c | N | LEA-047 | CTR-MCT 카운터 증가 있음
violations_lea057_nokey.c | P | LEA-057 | MCT 외부 루프 키 XOR 갱신 없음
violations_lea057_inner.c | P | LEA-057 | MCT 외부 루프 키 갱신 없음 (내부에만)
safe_lea057_xor.c | N | LEA-057 | key[k] ^= ct[k] 갱신 있음
safe_lea057_assign.c | N | LEA-057 | key[k] = key[k] ^ ct[k] 갱신 있음
violations_ctr001_dec.c | P | CTR-001 | ctr_decrypt에서 lea_decrypt 호출
violations_ctr001_encdec.c | P | CTR-001 | 암·복호화 모두 lea_decrypt 호출
safe_ctr001_enc.c | N | CTR-001 | 암·복호화 모두 lea_encrypt 사용
safe_ctr001_sym.c | N | CTR-001 | 단일 lea_ctr 함수로 대칭 구현
safe_ctr001_noctr.c | N | CTR-001 | CTR 함수 없음 → checker None → 정상
safe_ctr001_xor.c | N | CTR-001 | block_cipher_enc 사용 (lea_decrypt 없음)
violations_lea003_wrong.c | P | LEA-003 | 키 스케줄 라운드 수 20 (잘못된 값)
violations_lea003_rounds.c | P | LEA-003 | key_setup 라운드 수 16 (잘못된 값)
safe_lea003_24.c | N | LEA-003 | 128비트 → 24 라운드 정상
safe_lea003_macro.c | N | LEA-003 | 매크로 상수 사용 → 판단 불가(safe)
violations_com001_loop.c | P | COM-001 | memset 있지만 안전 제로화 누락
violations_com001_plain.c | P | COM-001 | 일반 memset으로 key 제거 (unsafe)
safe_com001_loop.c | N | COM-001 | for 루프 직접 제로화 정상
safe_com001_memsets.c | N | COM-001 | memset_s 안전 제로화 정상
violations_lea003_192.c | P | LEA-003 | 192-bit key schedule uses 26 rounds instead of 28
violations_lea003_256.c | P | LEA-003 | 256-bit key schedule uses 30 rounds instead of 32
safe_lea003_192.c | N | LEA-003 | correct 192-bit key -> 28 rounds
safe_lea003_256.c | N | LEA-003 | correct 256-bit key -> 32 rounds
safe_lea040_obo.c | N | LEA-040 | i<=23 normalizes to 24 rounds (functionally correct)
violations_lea040_under.c | P | LEA-040 | undercount i<23 in encrypt round loop (should be 24)
safe_lea040_correct.c | N | LEA-040 | correct i<24 round loop in encrypt
violations_com004_rand.c | P | COM-004 | rand()/srand(time(NULL)) for key generation
violations_com004_time.c | P | COM-004 | time(NULL) as key seed
safe_com004_urandom.c | N | COM-004 | /dev/urandom for cryptographic key
safe_com004_getrandom.c | N | COM-004 | getrandom() for cryptographic key
violations_cbc003_rand.c | P | CBC-003 | IV generated with rand() (non-CSPRNG)
violations_cbc003_const.c | P | CBC-003 | IV is hardcoded constant zeros
safe_cbc003_csprng.c | N | CBC-003 | IV generated via getrandom() CSPRNG
violations_gcm003_counter.c | P | GCM-003 | lea_gcm_set_ctr called before lea_gcm_init
safe_gcm003_random.c | N | GCM-003 | correct GCM API order with random nonce
violations_com003_32byte.c | P | COM-003 | 32-byte hardcoded key with 8+ hex values
safe_com003_derived.c | N | COM-003 | key derived from KDF not hardcoded
violations_ccm005_noclean.c | P | CCM-005 | CCM context not zeroed after use
safe_ccm005_clean.c | N | CCM-005 | CCM context zeroed with memset_s
violations_gcm005_noclean.c | P | GCM-005 | GCM context not zeroed after use
safe_gcm005_clean.c | N | GCM-005 | GCM context zeroed with memset_s
violations_cbc004_noclean.c | P | CBC-004 | CBC IV and local key not zeroed
safe_cbc004_clean.c | N | CBC-004 | CBC IV and local key zeroed with memset_s
violations_ctr003_fixed.c | P | CTR-003 | CTR nonce is a fixed/constant value
safe_ctr003_random.c | N | CTR-003 | CTR nonce from getrandom() CSPRNG
violations_cmac002_memcmp.c | P | CMAC-002 | memcmp for MAC comparison (timing leak)
safe_cmac002_const.c | N | CMAC-002 | constant-time comparison for MAC
violations_com002_nocheck.c | P | COM-002 | return value of lea_set_key not checked
safe_com002_checked.c | N | COM-002 | all return values properly checked
violations_lea044_leak.c | P | LEA-044 | key in global/static scope leaks after use
safe_lea044_local.c | N | LEA-044 | key local and zeroed with memset_s
violations_ecb002_nocheck2.c | P | ECB-002 | ecb_cipher without len%%16 alignment check
safe_ecb002_checked2.c | N | ECB-002 | ecb_cipher with len%%16 alignment check
violations_lea047_ctr2.c | P | LEA-047 | CTR-MCT without counter increment
safe_lea047_ctr2.c | N | LEA-047 | CTR-MCT with correct counter increment
