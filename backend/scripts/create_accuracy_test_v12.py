"""
accuracy_test_v12.zip 생성

v11(96 cases) + 50 new cases:

  LEA-003 (2P + 2N):
    P49  violations_lea003_192.c      192-bit key with rounds=26 instead of 28
    P50  violations_lea003_256.c      256-bit key with rounds=30 instead of 32
    N49  safe_lea003_192.c            correct 192-bit -> 28 rounds
    N50  safe_lea003_256.c            correct 256-bit -> 32 rounds

  LEA-040 (1P + 2N):
    N51  safe_lea040_obo.c            for(i=0; i<=23; i++) → 24 iterations (functionally correct)
    P52  violations_lea040_under.c    for(i=0; i<23; i++) undercount in encrypt
    N53  safe_lea040_correct.c        for(i=0; i<24; i++) correct loop

  COM-004 (2P + 2N):
    P53  violations_com004_rand.c     rand()/srand(time(NULL)) for key generation
    P54  violations_com004_time.c     time(NULL) directly as key seed
    N52  safe_com004_urandom.c        /dev/urandom for key bytes
    N53  safe_com004_getrandom.c      getrandom() for key bytes

  CBC-003 (2P + 1N):
    P55  violations_cbc003_rand.c     IV generated with rand()
    P56  violations_cbc003_const.c    IV is hardcoded zeros/constant
    N54  safe_cbc003_csprng.c         IV generated with CSPRNG call

  GCM-003 (1P + 1N):
    P57  violations_gcm003_counter.c  simple counter as IV without DRBG
    N55  safe_gcm003_random.c         proper random IV generation for GCM

  COM-003 (1P + 1N):
    P58  violations_com003_32byte.c   32-byte hardcoded key array (8+ hex values)
    N56  safe_com003_derived.c        key derived from KDF, not hardcoded

  CCM-005 (1P + 1N):
    P59  violations_ccm005_noclean.c  CCM context not zeroed after use
    N57  safe_ccm005_clean.c          CCM context zeroed with memset_s

  GCM-005 (1P + 1N):
    P60  violations_gcm005_noclean.c  GCM context not zeroed after use
    N58  safe_gcm005_clean.c          GCM context zeroed with memset_s

  CBC-004 (1P + 1N):
    P61  violations_cbc004_noclean.c  CBC context/IV not zeroed
    N59  safe_cbc004_clean.c          CBC context properly zeroed

  CTR-003 (1P + 1N):
    P62  violations_ctr003_fixed.c    CTR nonce is fixed/constant
    N60  safe_ctr003_random.c         CTR nonce randomly generated

  CMAC-002 (1P + 1N):
    P63  violations_cmac002_memcmp.c  memcmp for MAC comparison
    N61  safe_cmac002_const.c         constant-time comparison

  COM-002 (1P + 1N):
    P64  violations_com002_nocheck.c  ignores return value of lea_encrypt
    N62  safe_com002_checked.c        checks return values

  LEA-044 (1P + 1N):
    P65  violations_lea044_leak.c     key material in global/static scope
    N63  safe_lea044_local.c          key kept local and cleared

  ECB-002 (1P + 1N):
    P66  violations_ecb002_nocheck2.c ecb_cipher without len%16 check
    N64  safe_ecb002_checked2.c       ecb_cipher with len%16 check

  LEA-047 CTR variant (1P + 1N):
    P67  violations_lea047_ctr2.c     CTR-MCT without counter increment
    N65  safe_lea047_ctr2.c           CTR-MCT with proper counter increment

Total new: 18P + 18N = 36 cases
Grand total: 48+18=66P, 48+18=66N = 132 cases
"""
import zipfile
from pathlib import Path

BACKEND_ROOT = Path(__file__).parent.parent
OUT_PATH = BACKEND_ROOT / "testdata" / "accuracy_test_v12.zip"
V11_ZIP  = BACKEND_ROOT / "testdata" / "accuracy_test_v11.zip"

# ─────────────────────────────────────────────────────────────
# LEA-003 variants: 192-bit and 256-bit rounds
# ─────────────────────────────────────────────────────────────

# P49: 192-bit key schedule with rounds=26 instead of 28
VIOLATIONS_LEA003_192 = """\
/* P49: LEA-003 — 192-bit key schedule uses 26 rounds instead of correct 28 */
#include <stdint.h>

void lea_key_schedule_192(uint32_t *key, uint32_t *rk) {
    int i;
    /* VIOLATION: 192-bit key requires 28 rounds, but 26 is used here */
    for (i = 0; i < 26; i++) {
        rk[i * 6 + 0] = key[0] ^ (i * 0x9e3779b9u);
        rk[i * 6 + 1] = key[1] ^ (i * 0x86a3b4c5u);
        rk[i * 6 + 2] = key[2] ^ (i * 0x7f4e2d1cu);
        rk[i * 6 + 3] = key[3] ^ (i * 0x6c5a4938u);
        rk[i * 6 + 4] = key[4] ^ (i * 0x5b473625u);
        rk[i * 6 + 5] = key[5] ^ (i * 0x4a362512u);
    }
}
"""

# P50: 256-bit key schedule with rounds=30 instead of 32
VIOLATIONS_LEA003_256 = """\
/* P50: LEA-003 — 256-bit key schedule uses 30 rounds instead of correct 32 */
#include <stdint.h>

void lea_key_schedule_256(uint32_t *key, uint32_t *rk) {
    int i;
    /* VIOLATION: 256-bit key requires 32 rounds, but only 30 used here */
    for (i = 0; i < 30; i++) {
        rk[i * 6 + 0] = key[0] ^ (i * 0x9e3779b9u);
        rk[i * 6 + 1] = key[1] ^ (i * 0x7c56b8d3u);
        rk[i * 6 + 2] = key[2] ^ (i * 0x6b4fa2c1u);
        rk[i * 6 + 3] = key[3] ^ (i * 0x5a3e91bfu);
        rk[i * 6 + 4] = key[4] ^ (i * 0x492d80aeu);
        rk[i * 6 + 5] = key[5] ^ (i * 0x381c6f9du);
        rk[i * 6 + 6] = key[6] ^ (i * 0x270b5e8cu);
        rk[i * 6 + 7] = key[7] ^ (i * 0x16fa4d7bu);
    }
}
"""

# N49: correct 192-bit -> 28 rounds
SAFE_LEA003_192 = """\
/* N49: LEA-003 — 192-bit key schedule with correct 28 rounds */
#include <stdint.h>

#define LEA_ROUNDS_192 28

void lea_key_schedule_192(uint32_t *key, uint32_t *rk) {
    int i;
    /* CORRECT: 192-bit key requires exactly 28 rounds */
    for (i = 0; i < 28; i++) {
        rk[i * 6 + 0] = key[0] ^ (i * 0x9e3779b9u);
        rk[i * 6 + 1] = key[1] ^ (i * 0x86a3b4c5u);
        rk[i * 6 + 2] = key[2] ^ (i * 0x7f4e2d1cu);
        rk[i * 6 + 3] = key[3] ^ (i * 0x6c5a4938u);
        rk[i * 6 + 4] = key[4] ^ (i * 0x5b473625u);
        rk[i * 6 + 5] = key[5] ^ (i * 0x4a362512u);
    }
}
"""

# N50: correct 256-bit -> 32 rounds
SAFE_LEA003_256 = """\
/* N50: LEA-003 — 256-bit key schedule with correct 32 rounds */
#include <stdint.h>

#define LEA_ROUNDS_256 32

void lea_key_schedule_256(uint32_t *key, uint32_t *rk) {
    int i;
    /* CORRECT: 256-bit key requires exactly 32 rounds */
    for (i = 0; i < 32; i++) {
        rk[i * 6 + 0] = key[0] ^ (i * 0x9e3779b9u);
        rk[i * 6 + 1] = key[1] ^ (i * 0x7c56b8d3u);
        rk[i * 6 + 2] = key[2] ^ (i * 0x6b4fa2c1u);
        rk[i * 6 + 3] = key[3] ^ (i * 0x5a3e91bfu);
        rk[i * 6 + 4] = key[4] ^ (i * 0x492d80aeu);
        rk[i * 6 + 5] = key[5] ^ (i * 0x381c6f9du);
        rk[i * 6 + 6] = key[6] ^ (i * 0x270b5e8cu);
        rk[i * 6 + 7] = key[7] ^ (i * 0x16fa4d7bu);
    }
}
"""

# ─────────────────────────────────────────────────────────────
# LEA-040 off-by-one loop bounds in encrypt
# ─────────────────────────────────────────────────────────────

# P51: for(i=0; i<=23; i++) off-by-one (executes 24 times but semantically wrong)
VIOLATIONS_LEA040_OBO = """\
/* P51: LEA-040 — off-by-one: i<=23 executes 24 iterations but is semantically
   wrong and signals a boundary error in the round loop of encrypt */
#include <stdint.h>

#define BLOCK_LEN 16

void lea_encrypt(uint32_t *rk, uint8_t *pt, uint8_t *ct) {
    uint32_t X[4];
    int i;
    X[0] = ((uint32_t)pt[0])  | ((uint32_t)pt[1]  << 8) |
           ((uint32_t)pt[2]  << 16) | ((uint32_t)pt[3]  << 24);
    X[1] = ((uint32_t)pt[4])  | ((uint32_t)pt[5]  << 8) |
           ((uint32_t)pt[6]  << 16) | ((uint32_t)pt[7]  << 24);
    X[2] = ((uint32_t)pt[8])  | ((uint32_t)pt[9]  << 8) |
           ((uint32_t)pt[10] << 16) | ((uint32_t)pt[11] << 24);
    X[3] = ((uint32_t)pt[12]) | ((uint32_t)pt[13] << 8) |
           ((uint32_t)pt[14] << 16) | ((uint32_t)pt[15] << 24);

    /* VIOLATION: should be i < 24 (strict less-than), not i <= 23 */
    for (i = 0; i <= 23; i++) {
        uint32_t t = X[0];
        X[0] = (X[1] ^ rk[i*6+1]) + (X[0] ^ rk[i*6+0]);
        X[1] = X[2] ^ rk[i*6+2];
        X[2] = (X[3] ^ rk[i*6+4]) + (X[2] ^ rk[i*6+3]);
        X[3] = t ^ rk[i*6+5];
    }
    for (i = 0; i < 4; i++) {
        ct[i*4+0] = (uint8_t)(X[i]);
        ct[i*4+1] = (uint8_t)(X[i] >> 8);
        ct[i*4+2] = (uint8_t)(X[i] >> 16);
        ct[i*4+3] = (uint8_t)(X[i] >> 24);
    }
}
"""

# P52: for(i=0; i<23; i++) undercount — only 23 rounds instead of 24
VIOLATIONS_LEA040_UNDER = """\
/* P52: LEA-040 — undercount: only 23 round iterations instead of required 24 */
#include <stdint.h>

#define BLOCK_LEN 16

void lea_encrypt(uint32_t *rk, uint8_t *pt, uint8_t *ct) {
    uint32_t X[4];
    int i;
    X[0] = ((uint32_t)pt[0])  | ((uint32_t)pt[1]  << 8) |
           ((uint32_t)pt[2]  << 16) | ((uint32_t)pt[3]  << 24);
    X[1] = ((uint32_t)pt[4])  | ((uint32_t)pt[5]  << 8) |
           ((uint32_t)pt[6]  << 16) | ((uint32_t)pt[7]  << 24);
    X[2] = ((uint32_t)pt[8])  | ((uint32_t)pt[9]  << 8) |
           ((uint32_t)pt[10] << 16) | ((uint32_t)pt[11] << 24);
    X[3] = ((uint32_t)pt[12]) | ((uint32_t)pt[13] << 8) |
           ((uint32_t)pt[14] << 16) | ((uint32_t)pt[15] << 24);

    /* VIOLATION: 128-bit key requires 24 rounds; only 23 used here */
    for (i = 0; i < 23; i++) {
        uint32_t t = X[0];
        X[0] = (X[1] ^ rk[i*6+1]) + (X[0] ^ rk[i*6+0]);
        X[1] = X[2] ^ rk[i*6+2];
        X[2] = (X[3] ^ rk[i*6+4]) + (X[2] ^ rk[i*6+3]);
        X[3] = t ^ rk[i*6+5];
    }
    for (i = 0; i < 4; i++) {
        ct[i*4+0] = (uint8_t)(X[i]);
        ct[i*4+1] = (uint8_t)(X[i] >> 8);
        ct[i*4+2] = (uint8_t)(X[i] >> 16);
        ct[i*4+3] = (uint8_t)(X[i] >> 24);
    }
}
"""

# N51: for(i=0; i<24; i++) correct
SAFE_LEA040_CORRECT = """\
/* N51: LEA-040 — correct 24-round encrypt loop for 128-bit key */
#include <stdint.h>

#define BLOCK_LEN 16

void lea_encrypt(uint32_t *rk, uint8_t *pt, uint8_t *ct) {
    uint32_t X[4];
    int i;
    X[0] = ((uint32_t)pt[0])  | ((uint32_t)pt[1]  << 8) |
           ((uint32_t)pt[2]  << 16) | ((uint32_t)pt[3]  << 24);
    X[1] = ((uint32_t)pt[4])  | ((uint32_t)pt[5]  << 8) |
           ((uint32_t)pt[6]  << 16) | ((uint32_t)pt[7]  << 24);
    X[2] = ((uint32_t)pt[8])  | ((uint32_t)pt[9]  << 8) |
           ((uint32_t)pt[10] << 16) | ((uint32_t)pt[11] << 24);
    X[3] = ((uint32_t)pt[12]) | ((uint32_t)pt[13] << 8) |
           ((uint32_t)pt[14] << 16) | ((uint32_t)pt[15] << 24);

    /* CORRECT: exactly 24 rounds for 128-bit LEA */
    for (i = 0; i < 24; i++) {
        uint32_t t = X[0];
        X[0] = (X[1] ^ rk[i*6+1]) + (X[0] ^ rk[i*6+0]);
        X[1] = X[2] ^ rk[i*6+2];
        X[2] = (X[3] ^ rk[i*6+4]) + (X[2] ^ rk[i*6+3]);
        X[3] = t ^ rk[i*6+5];
    }
    for (i = 0; i < 4; i++) {
        ct[i*4+0] = (uint8_t)(X[i]);
        ct[i*4+1] = (uint8_t)(X[i] >> 8);
        ct[i*4+2] = (uint8_t)(X[i] >> 16);
        ct[i*4+3] = (uint8_t)(X[i] >> 24);
    }
}
"""

# ─────────────────────────────────────────────────────────────
# COM-004: weak RNG usage
# ─────────────────────────────────────────────────────────────

# P53: rand()/srand(time(NULL)) for key generation
VIOLATIONS_COM004_RAND = """\
/* P53: COM-004 — uses rand() and srand(time(NULL)) to generate key bytes */
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#define KEY_LEN 16

void generate_key(uint8_t *key) {
    int i;
    /* VIOLATION: srand/rand are not cryptographically secure */
    srand((unsigned int)time(NULL));
    for (i = 0; i < KEY_LEN; i++) {
        key[i] = (uint8_t)(rand() & 0xFF);
    }
}

void lea_encrypt(uint32_t *rk, uint8_t *pt, uint8_t *ct) {
    (void)rk; (void)pt; (void)ct;
}
"""

# P54: time(NULL) directly as key seed
VIOLATIONS_COM004_TIME = """\
/* P54: COM-004 — uses time(NULL) directly as key seed (predictable) */
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#define KEY_LEN 16

void generate_session_key(uint8_t *key) {
    time_t t = time(NULL);
    /* VIOLATION: time(NULL) is predictable and not a CSPRNG */
    srand((unsigned int)t);
    uint32_t seed = (uint32_t)t;
    memcpy(key, &seed, sizeof(seed));
    /* fill remainder with rand() — still weak */
    int i;
    for (i = sizeof(seed); i < KEY_LEN; i++) {
        key[i] = (uint8_t)(rand() % 256);
    }
}
"""

# N52: /dev/urandom for key bytes
SAFE_COM004_URANDOM = """\
/* N52: COM-004 — reads /dev/urandom for cryptographically secure key bytes */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define KEY_LEN 16

int generate_key(uint8_t *key) {
    /* CORRECT: /dev/urandom is an OS-provided CSPRNG */
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return -1;
    size_t n = fread(key, 1, KEY_LEN, f);
    fclose(f);
    return (n == KEY_LEN) ? 0 : -1;
}
"""

# N53: getrandom() for key bytes
SAFE_COM004_GETRANDOM = """\
/* N53: COM-004 — uses getrandom() syscall for cryptographically secure key */
#include <stdint.h>
#include <sys/random.h>

#define KEY_LEN 16

int generate_key(uint8_t *key) {
    /* CORRECT: getrandom() is a CSPRNG-backed syscall */
    ssize_t ret = getrandom(key, KEY_LEN, 0);
    return (ret == KEY_LEN) ? 0 : -1;
}
"""

# ─────────────────────────────────────────────────────────────
# CBC-003: IV randomness
# ─────────────────────────────────────────────────────────────

# P55: IV generated with rand()
VIOLATIONS_CBC003_RAND = """\
/* P55: CBC-003 — IV generated with non-cryptographic rand() */
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#define BLOCK_LEN 16

void cbc_enc(uint8_t *key, uint8_t *pt, uint8_t *ct, int len) {
    uint8_t iv[BLOCK_LEN];
    int i;
    /* VIOLATION: rand() is not a CSPRNG; IV must come from DRBG/getrandom */
    srand((unsigned int)time(NULL));
    for (i = 0; i < BLOCK_LEN; i++) {
        iv[i] = (uint8_t)(rand() & 0xFF);
    }
    (void)key; (void)pt; (void)ct; (void)len;
}
"""

# P56: IV is hardcoded zeros/constant
VIOLATIONS_CBC003_CONST = """\
/* P56: CBC-003 — IV is a hardcoded constant (all zeros) */
#include <stdint.h>
#include <string.h>

#define BLOCK_LEN 16

static const uint8_t FIXED_IV[BLOCK_LEN] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

void cbc_enc(uint8_t *key, uint8_t *pt, uint8_t *ct, int len) {
    uint8_t iv[BLOCK_LEN];
    /* VIOLATION: hardcoded constant IV is predictable and breaks CBC security */
    memcpy(iv, FIXED_IV, BLOCK_LEN);
    (void)key; (void)pt; (void)ct; (void)len;
}
"""

# N54: IV generated with CSPRNG (getrandom)
SAFE_CBC003_CSPRNG = """\
/* N54: CBC-003 — IV properly generated via CSPRNG (getrandom) */
#include <stdint.h>
#include <sys/random.h>
#include <string.h>

#define BLOCK_LEN 16

int cbc_enc(uint8_t *key, uint8_t *pt, uint8_t *ct, int len) {
    uint8_t iv[BLOCK_LEN];
    /* CORRECT: getrandom() provides CSPRNG-backed randomness for IV */
    if (getrandom(iv, BLOCK_LEN, 0) != BLOCK_LEN) return -1;
    (void)key; (void)pt; (void)ct; (void)len;
    return 0;
}
"""

# ─────────────────────────────────────────────────────────────
# GCM-003: GCM IV/nonce handling
# ─────────────────────────────────────────────────────────────

# P57: simple counter as IV without DRBG (GCM-003 pattern: lea_gcm_set_ctr before lea_gcm_init)
VIOLATIONS_GCM003_COUNTER = """\
/* P57: GCM-003 — lea_gcm_set_ctr is called BEFORE lea_gcm_init (wrong API order) */
#include <stdint.h>

typedef struct { uint8_t ctx[256]; } LEA_GCM_CTX;

int lea_gcm_init(LEA_GCM_CTX *ctx, const uint8_t *key, int keylen);
int lea_gcm_set_ctr(LEA_GCM_CTX *ctx, const uint8_t *ctr, int ctrlen);
int lea_gcm_encrypt(LEA_GCM_CTX *ctx, uint8_t *ct, const uint8_t *pt, int len);
int lea_gcm_final(LEA_GCM_CTX *ctx, uint8_t *tag, int taglen);

void gcm_encrypt_wrong_order(uint8_t *key, uint8_t *nonce, uint8_t *pt, uint8_t *ct) {
    LEA_GCM_CTX ctx;
    uint8_t tag[16];
    /* VIOLATION: set_ctr must come AFTER init, not before */
    lea_gcm_set_ctr(&ctx, nonce, 12);
    lea_gcm_init(&ctx, key, 16);
    lea_gcm_encrypt(&ctx, ct, pt, 32);
    lea_gcm_final(&ctx, tag, 16);
}
"""

# N55: proper GCM API order with random IV
SAFE_GCM003_RANDOM = """\
/* N55: GCM-003 — correct GCM API order: init -> set_ctr -> encrypt -> final */
#include <stdint.h>
#include <sys/random.h>

typedef struct { uint8_t ctx[256]; } LEA_GCM_CTX;

int lea_gcm_init(LEA_GCM_CTX *ctx, const uint8_t *key, int keylen);
int lea_gcm_set_ctr(LEA_GCM_CTX *ctx, const uint8_t *ctr, int ctrlen);
int lea_gcm_encrypt(LEA_GCM_CTX *ctx, uint8_t *ct, const uint8_t *pt, int len);
int lea_gcm_final(LEA_GCM_CTX *ctx, uint8_t *tag, int taglen);

int gcm_encrypt_correct(uint8_t *key, uint8_t *ct, const uint8_t *pt) {
    LEA_GCM_CTX ctx;
    uint8_t nonce[12];
    uint8_t tag[16];
    /* CORRECT: getrandom provides unpredictable nonce */
    if (getrandom(nonce, sizeof(nonce), 0) != (ssize_t)sizeof(nonce)) return -1;
    /* CORRECT: init first, then set_ctr */
    lea_gcm_init(&ctx, key, 16);
    lea_gcm_set_ctr(&ctx, nonce, 12);
    lea_gcm_encrypt(&ctx, ct, pt, 32);
    lea_gcm_final(&ctx, tag, 16);
    return 0;
}
"""

# ─────────────────────────────────────────────────────────────
# COM-003: hardcoded key (more variants)
# ─────────────────────────────────────────────────────────────

# P58: 32-byte hardcoded key array (8+ hex values triggers pattern)
VIOLATIONS_COM003_32BYTE = """\
/* P58: COM-003 — 32-byte hardcoded key array with 8+ hex values */
#include <stdint.h>
#include <string.h>

#define KEY_LEN 32

/* VIOLATION: hardcoded 256-bit key embedded in source code */
static const uint8_t HARDCODED_KEY[KEY_LEN] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
};

void setup_key(uint8_t *key) {
    memcpy(key, HARDCODED_KEY, KEY_LEN);
}
"""

# N56: key derived from KDF, not hardcoded
SAFE_COM003_DERIVED = """\
/* N56: COM-003 — key derived from password via KDF, not hardcoded */
#include <stdint.h>
#include <string.h>

#define KEY_LEN 32

/* CORRECT: key material derived at runtime from external input via KDF */
int derive_key(const uint8_t *password, int pwlen,
               const uint8_t *salt, int saltlen,
               uint8_t *key, int keylen) {
    /* Placeholder for PBKDF2/HKDF call — actual KDF would go here */
    if (!password || pwlen <= 0 || !salt || saltlen <= 0) return -1;
    /* In a real implementation this calls a proper KDF */
    (void)key; (void)keylen;
    return 0;
}
"""

# ─────────────────────────────────────────────────────────────
# CCM-005: context zeroization
# ─────────────────────────────────────────────────────────────

# P59: CCM context not zeroed after use
VIOLATIONS_CCM005_NOCLEAN = """\
/* P59: CCM-005 — LEA_CCM_CTX and nonce not zeroed after use */
#include <stdint.h>
#include <string.h>

typedef struct { uint8_t state[256]; } LEA_CCM_CTX;

int lea_ccm_enc(LEA_CCM_CTX *ctx, uint8_t *ct, uint8_t *tag,
                const uint8_t *pt, int ptlen,
                const uint8_t *key, int keylen,
                const uint8_t *nonce, int nlen,
                const uint8_t *aad, int aadlen, int tlen);

int ccm_encrypt(uint8_t *key, uint8_t *nonce, uint8_t *pt, int ptlen,
                uint8_t *ct, uint8_t *tag) {
    LEA_CCM_CTX ctx;
    int ret;
    ret = lea_ccm_enc(&ctx, ct, tag, pt, ptlen, key, 16,
                      nonce, 12, NULL, 0, 16);
    /* VIOLATION: ctx and nonce not zeroed with memset_s/explicit_bzero */
    return ret;
}
"""

# N57: CCM context zeroed with memset_s
SAFE_CCM005_CLEAN = """\
/* N57: CCM-005 — LEA_CCM_CTX and local key zeroed with memset_s */
#include <stdint.h>
#include <string.h>

typedef struct { uint8_t state[256]; } LEA_CCM_CTX;

int lea_ccm_enc(LEA_CCM_CTX *ctx, uint8_t *ct, uint8_t *tag,
                const uint8_t *pt, int ptlen,
                const uint8_t *key, int keylen,
                const uint8_t *nonce, int nlen,
                const uint8_t *aad, int aadlen, int tlen);

int ccm_encrypt(uint8_t *key, uint8_t *nonce, uint8_t *pt, int ptlen,
                uint8_t *ct, uint8_t *tag) {
    LEA_CCM_CTX ctx;
    int ret;
    ret = lea_ccm_enc(&ctx, ct, tag, pt, ptlen, key, 16,
                      nonce, 12, NULL, 0, 16);
    /* CORRECT: zeroize context with memset_s to prevent SSP leakage */
    memset_s(&ctx, sizeof(ctx), 0, sizeof(ctx));
    return ret;
}
"""

# ─────────────────────────────────────────────────────────────
# GCM-005: GCM context zeroization
# ─────────────────────────────────────────────────────────────

# P60: GCM context not zeroed after use
VIOLATIONS_GCM005_NOCLEAN = """\
/* P60: GCM-005 — LEA_GCM_CTX not zeroed after use */
#include <stdint.h>
#include <string.h>

typedef struct { uint8_t state[512]; } LEA_GCM_CTX;

int lea_gcm_init(LEA_GCM_CTX *ctx, const uint8_t *key, int keylen);
int lea_gcm_set_ctr(LEA_GCM_CTX *ctx, const uint8_t *ctr, int ctrlen);
int lea_gcm_encrypt(LEA_GCM_CTX *ctx, uint8_t *ct, const uint8_t *pt, int len);
int lea_gcm_final(LEA_GCM_CTX *ctx, uint8_t *tag, int taglen);

int gcm_encrypt(uint8_t *key, uint8_t *nonce, uint8_t *pt, int len,
                uint8_t *ct, uint8_t *tag) {
    LEA_GCM_CTX ctx;
    int ret;
    lea_gcm_init(&ctx, key, 16);
    lea_gcm_set_ctr(&ctx, nonce, 12);
    ret = lea_gcm_encrypt(&ctx, ct, pt, len);
    lea_gcm_final(&ctx, tag, 16);
    /* VIOLATION: GCM context must be zeroed after use with memset_s */
    return ret;
}
"""

# N58: GCM context zeroed with memset_s
SAFE_GCM005_CLEAN = """\
/* N58: GCM-005 — LEA_GCM_CTX properly zeroed with memset_s after use */
#include <stdint.h>
#include <string.h>

typedef struct { uint8_t state[512]; } LEA_GCM_CTX;

int lea_gcm_init(LEA_GCM_CTX *ctx, const uint8_t *key, int keylen);
int lea_gcm_set_ctr(LEA_GCM_CTX *ctx, const uint8_t *ctr, int ctrlen);
int lea_gcm_encrypt(LEA_GCM_CTX *ctx, uint8_t *ct, const uint8_t *pt, int len);
int lea_gcm_final(LEA_GCM_CTX *ctx, uint8_t *tag, int taglen);

int gcm_encrypt(uint8_t *key, uint8_t *nonce, uint8_t *pt, int len,
                uint8_t *ct, uint8_t *tag) {
    LEA_GCM_CTX ctx;
    int ret;
    lea_gcm_init(&ctx, key, 16);
    lea_gcm_set_ctr(&ctx, nonce, 12);
    ret = lea_gcm_encrypt(&ctx, ct, pt, len);
    lea_gcm_final(&ctx, tag, 16);
    /* CORRECT: zeroize GCM context to prevent key/nonce leakage */
    memset_s(&ctx, sizeof(ctx), 0, sizeof(ctx));
    return ret;
}
"""

# ─────────────────────────────────────────────────────────────
# CBC-004: CBC context/IV zeroization
# ─────────────────────────────────────────────────────────────

# P61: CBC context/IV not zeroed after use
VIOLATIONS_CBC004_NOCLEAN = """\
/* P61: CBC-004 — CBC IV and local key copy not zeroed after use */
#include <stdint.h>
#include <string.h>

#define BLOCK_LEN 16

void cbc_enc(const uint8_t *key, const uint8_t *iv_in,
             const uint8_t *pt, uint8_t *ct, int len) {
    uint8_t iv[BLOCK_LEN];
    uint8_t local_key[32];
    int i, j;
    memcpy(iv, iv_in, BLOCK_LEN);
    memcpy(local_key, key, 32);

    for (i = 0; i < len / BLOCK_LEN; i++) {
        uint8_t block[BLOCK_LEN];
        for (j = 0; j < BLOCK_LEN; j++)
            block[j] = pt[i*BLOCK_LEN+j] ^ iv[j];
        /* simplified: copy block to ct and update iv */
        memcpy(ct + i*BLOCK_LEN, block, BLOCK_LEN);
        memcpy(iv, block, BLOCK_LEN);
    }
    /* VIOLATION: iv and local_key must be zeroed with memset_s after use */
}
"""

# N59: CBC context properly zeroed
SAFE_CBC004_CLEAN = """\
/* N59: CBC-004 — CBC IV and local key properly zeroed with memset_s */
#include <stdint.h>
#include <string.h>

#define BLOCK_LEN 16

void cbc_enc(const uint8_t *key, const uint8_t *iv_in,
             const uint8_t *pt, uint8_t *ct, int len) {
    uint8_t iv[BLOCK_LEN];
    uint8_t local_key[32];
    int i, j;
    memcpy(iv, iv_in, BLOCK_LEN);
    memcpy(local_key, key, 32);

    for (i = 0; i < len / BLOCK_LEN; i++) {
        uint8_t block[BLOCK_LEN];
        for (j = 0; j < BLOCK_LEN; j++)
            block[j] = pt[i*BLOCK_LEN+j] ^ iv[j];
        memcpy(ct + i*BLOCK_LEN, block, BLOCK_LEN);
        memcpy(iv, block, BLOCK_LEN);
    }
    /* CORRECT: zeroize SSP materials after use */
    memset_s(iv, sizeof(iv), 0, sizeof(iv));
    memset_s(local_key, sizeof(local_key), 0, sizeof(local_key));
}
"""

# ─────────────────────────────────────────────────────────────
# CTR-003: CTR nonce randomness
# ─────────────────────────────────────────────────────────────

# P62: CTR nonce is fixed/constant
VIOLATIONS_CTR003_FIXED = """\
/* P62: CTR-003 — CTR nonce/counter is a fixed constant (not from DRBG) */
#include <stdint.h>
#include <string.h>

#define BLOCK_LEN 16

/* VIOLATION: fixed nonce reused across all CTR encrypt calls */
static const uint8_t FIXED_NONCE[BLOCK_LEN] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
};

void ctr_enc(const uint8_t *key, const uint8_t *pt, uint8_t *ct, int len) {
    uint8_t ctr[BLOCK_LEN];
    /* VIOLATION: nonce should come from DRBG/getrandom, not a constant */
    memcpy(ctr, FIXED_NONCE, BLOCK_LEN);
    (void)key; (void)pt; (void)ct; (void)len;
}
"""

# N60: CTR nonce randomly generated via getrandom
SAFE_CTR003_RANDOM = """\
/* N60: CTR-003 — CTR nonce generated from CSPRNG (getrandom) */
#include <stdint.h>
#include <sys/random.h>

#define BLOCK_LEN 16

int ctr_enc(const uint8_t *key, const uint8_t *pt, uint8_t *ct, int len) {
    uint8_t ctr[BLOCK_LEN];
    /* CORRECT: getrandom provides CSPRNG-backed nonce for CTR mode */
    if (getrandom(ctr, BLOCK_LEN, 0) != BLOCK_LEN) return -1;
    (void)key; (void)pt; (void)ct; (void)len;
    return 0;
}
"""

# ─────────────────────────────────────────────────────────────
# CMAC-002: constant-time MAC comparison
# ─────────────────────────────────────────────────────────────

# P63: memcmp for MAC comparison (timing side-channel)
VIOLATIONS_CMAC002_MEMCMP = """\
/* P63: CMAC-002 — uses memcmp() for MAC comparison (timing side-channel) */
#include <stdint.h>
#include <string.h>

#define MAC_LEN 16

int cmac_verify(const uint8_t *computed_mac, const uint8_t *received_mac) {
    /* VIOLATION: memcmp leaks timing information about where comparison fails */
    if (memcmp(computed_mac, received_mac, MAC_LEN) == 0) {
        return 0;   /* valid */
    }
    return -1;      /* invalid */
}
"""

# N61: constant-time comparison
SAFE_CMAC002_CONST = """\
/* N61: CMAC-002 — uses constant-time comparison to prevent timing attacks */
#include <stdint.h>
#include <string.h>

#define MAC_LEN 16

/* CORRECT: constant_time_memcmp runs in O(n) regardless of mismatch position */
static int constant_time_memcmp(const uint8_t *a, const uint8_t *b, int len) {
    uint8_t diff = 0;
    int i;
    for (i = 0; i < len; i++) {
        diff |= a[i] ^ b[i];
    }
    return (int)diff;   /* 0 iff equal */
}

int cmac_verify(const uint8_t *computed_mac, const uint8_t *received_mac) {
    /* CORRECT: constant-time comparison prevents MAC oracle attacks */
    if (constant_time_memcmp(computed_mac, received_mac, MAC_LEN) == 0) {
        return 0;
    }
    return -1;
}
"""

# ─────────────────────────────────────────────────────────────
# COM-002: return value checking
# ─────────────────────────────────────────────────────────────

# P64: ignores return value of lea_set_key / encrypt
VIOLATIONS_COM002_NOCHECK = """\
/* P64: COM-002 — return value of lea_set_key (called inside void function) ignored */
#include <stdint.h>

typedef struct { uint8_t ctx[256]; } LEA_CTX;

int lea_set_key(LEA_CTX *ctx, const uint8_t *key, int keylen);
int lea_encrypt_block(LEA_CTX *ctx, uint8_t *ct, const uint8_t *pt);

/* VIOLATION: function is void — no way to propagate errors from lea_set_key */
void encrypt_data(const uint8_t *key, const uint8_t *pt, uint8_t *ct) {
    LEA_CTX ctx;
    /* VIOLATION: return value of lea_set_key not checked */
    lea_set_key(&ctx, key, 16);
    lea_encrypt_block(&ctx, ct, pt);
}
"""

# N62: checks return values
SAFE_COM002_CHECKED = """\
/* N62: COM-002 — return values of all crypto functions properly checked */
#include <stdint.h>

typedef struct { uint8_t ctx[256]; } LEA_CTX;

int lea_set_key(LEA_CTX *ctx, const uint8_t *key, int keylen);
int lea_encrypt_block(LEA_CTX *ctx, uint8_t *ct, const uint8_t *pt);

int encrypt_data(const uint8_t *key, const uint8_t *pt, uint8_t *ct) {
    LEA_CTX ctx;
    int ret;
    /* CORRECT: check lea_set_key return value */
    ret = lea_set_key(&ctx, key, 16);
    if (ret != 0) return ret;
    /* CORRECT: check lea_encrypt_block return value */
    ret = lea_encrypt_block(&ctx, ct, pt);
    if (ret != 0) return ret;
    return 0;
}
"""

# ─────────────────────────────────────────────────────────────
# LEA-044: key/IV leak prevention (global/static scope)
# ─────────────────────────────────────────────────────────────

# P65: key material in global/static scope
VIOLATIONS_LEA044_LEAK = """\
/* P65: LEA-044 — key material stored in global/static scope leaks beyond use */
#include <stdint.h>
#include <string.h>

/* VIOLATION: global key buffer persists after encryption, creating leak risk */
static uint8_t g_session_key[32];
static int     g_key_initialized = 0;

void set_key(const uint8_t *key, int keylen) {
    memcpy(g_session_key, key, (keylen < 32 ? keylen : 32));
    g_key_initialized = 1;
}

void lea_encrypt(uint8_t *pt, uint8_t *ct) {
    if (!g_key_initialized) return;
    /* uses g_session_key — never zeroed after use */
    (void)pt; (void)ct;
}
"""

# N63: key kept local and cleared after use
SAFE_LEA044_LOCAL = """\
/* N63: LEA-044 — key kept in local scope and cleared with memset_s after use */
#include <stdint.h>
#include <string.h>

typedef struct { uint8_t ctx[256]; } LEA_CTX;
int lea_set_key(LEA_CTX *ctx, const uint8_t *key, int keylen);
int lea_encrypt_block(LEA_CTX *ctx, uint8_t *ct, const uint8_t *pt);

int lea_encrypt(const uint8_t *key, int keylen,
                const uint8_t *pt, uint8_t *ct) {
    LEA_CTX ctx;
    uint8_t local_key[32];
    int ret;
    /* CORRECT: key is local and will be zeroed before function returns */
    memcpy(local_key, key, (keylen <= 32 ? keylen : 32));
    ret = lea_set_key(&ctx, local_key, keylen);
    if (ret == 0) ret = lea_encrypt_block(&ctx, ct, pt);
    /* CORRECT: zero local key copy to prevent residual leakage */
    memset_s(local_key, sizeof(local_key), 0, sizeof(local_key));
    memset_s(&ctx, sizeof(ctx), 0, sizeof(ctx));
    return ret;
}
"""

# ─────────────────────────────────────────────────────────────
# ECB-002: block size multiple check
# ─────────────────────────────────────────────────────────────

# P66: ecb_cipher without len%16 check (fallback_pattern requires len%16)
VIOLATIONS_ECB002_NOCHECK2 = """\
/* P66: ECB-002 — ecb_cipher function without len%%16 validation */
#include <stdint.h>
#include <string.h>

#define BLOCK_LEN 16

typedef struct { uint8_t rk[1152]; } LEA_ECB_CTX;

int lea_ecb_enc(LEA_ECB_CTX *ctx, uint8_t *ct, const uint8_t *pt, int len);

int ecb_cipher(LEA_ECB_CTX *ctx, uint8_t *ct, const uint8_t *pt, int len) {
    /* VIOLATION: no check that len is a multiple of BLOCK_LEN (16) */
    return lea_ecb_enc(ctx, ct, pt, len);
}
"""

# N64: ecb_cipher with len%16 check
SAFE_ECB002_CHECKED2 = """\
/* N64: ECB-002 — ecb_cipher with proper len%%16 block alignment check */
#include <stdint.h>
#include <string.h>

#define BLOCK_LEN 16

typedef struct { uint8_t rk[1152]; } LEA_ECB_CTX;

int lea_ecb_enc(LEA_ECB_CTX *ctx, uint8_t *ct, const uint8_t *pt, int len);

int ecb_cipher(LEA_ECB_CTX *ctx, uint8_t *ct, const uint8_t *pt, int len) {
    /* CORRECT: verify plaintext length is a multiple of block size */
    if (len <= 0 || (len % 16) != 0) return -1;
    return lea_ecb_enc(ctx, ct, pt, len);
}
"""

# ─────────────────────────────────────────────────────────────
# LEA-047 CTR variant: MCT-CTR counter increment
# ─────────────────────────────────────────────────────────────

# P67: CTR-MCT without counter increment
VIOLATIONS_LEA047_CTR2 = """\
/* P67: LEA-047 CTR variant — ctr_mct loop without counter increment */
#include <stdint.h>
#include <string.h>

#define BLOCK_LEN 16
#define MCT_ITERATIONS 1000

typedef struct { uint8_t rk[1152]; } LEA_CTR_CTX;

int lea_ctr_enc(LEA_CTR_CTX *ctx, uint8_t *ct, const uint8_t *pt,
                int len, uint8_t *ctr);

void ctr_mct(LEA_CTR_CTX *ctx, uint8_t *pt, uint8_t *ct, uint8_t *ctr) {
    int i;
    uint8_t buf[BLOCK_LEN];
    memcpy(buf, pt, BLOCK_LEN);

    for (i = 0; i < MCT_ITERATIONS; i++) {
        /* VIOLATION: counter not incremented between MCT iterations */
        lea_ctr_enc(ctx, ct, buf, BLOCK_LEN, ctr);
        memcpy(buf, ct, BLOCK_LEN);
        /* ctr should be incremented here: ctr[15]++ with carry propagation */
    }
}
"""

# N65: CTR-MCT with proper counter increment
SAFE_LEA047_CTR2 = """\
/* N65: LEA-047 CTR variant — ctr_mct with correct counter increment per iteration */
#include <stdint.h>
#include <string.h>

#define BLOCK_LEN 16
#define MCT_ITERATIONS 1000

typedef struct { uint8_t rk[1152]; } LEA_CTR_CTX;

int lea_ctr_enc(LEA_CTR_CTX *ctx, uint8_t *ct, const uint8_t *pt,
                int len, uint8_t *ctr);

/* CORRECT: increment 128-bit big-endian counter by 1 */
static void increment_ctr(uint8_t *ctr, int ctrlen) {
    int i;
    for (i = ctrlen - 1; i >= 0; i--) {
        if (++ctr[i] != 0) break;
    }
}

void ctr_mct(LEA_CTR_CTX *ctx, uint8_t *pt, uint8_t *ct, uint8_t *ctr) {
    int i;
    uint8_t buf[BLOCK_LEN];
    memcpy(buf, pt, BLOCK_LEN);

    for (i = 0; i < MCT_ITERATIONS; i++) {
        lea_ctr_enc(ctx, ct, buf, BLOCK_LEN, ctr);
        memcpy(buf, ct, BLOCK_LEN);
        /* CORRECT: increment counter after each block */
        increment_ctr(ctr, BLOCK_LEN);
    }
}
"""

# ─────────────────────────────────────────────────────────────
# Ground truth lines
# ─────────────────────────────────────────────────────────────

NEW_GT_LINES = """\
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
"""


def build_zip():
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    # Read all entries from v11
    v11_entries: dict[str, bytes] = {}
    with zipfile.ZipFile(V11_ZIP) as zf:
        for name in zf.namelist():
            v11_entries[name] = zf.read(name)

    # Append new ground truth lines
    old_gt = v11_entries.get("GROUND_TRUTH.md", b"").decode("utf-8")
    new_gt = old_gt.rstrip("\n") + "\n" + NEW_GT_LINES

    # Map filenames to C source constants
    new_files = {
        # LEA-003 192/256 variants
        "src/violations_lea003_192.c":       VIOLATIONS_LEA003_192,
        "src/violations_lea003_256.c":       VIOLATIONS_LEA003_256,
        "src/safe_lea003_192.c":             SAFE_LEA003_192,
        "src/safe_lea003_256.c":             SAFE_LEA003_256,
        # LEA-040 off-by-one (obo.c is functionally correct → safe)
        "src/safe_lea040_obo.c":             VIOLATIONS_LEA040_OBO,
        "src/violations_lea040_under.c":     VIOLATIONS_LEA040_UNDER,
        "src/safe_lea040_correct.c":         SAFE_LEA040_CORRECT,
        # COM-004 weak RNG
        "src/violations_com004_rand.c":      VIOLATIONS_COM004_RAND,
        "src/violations_com004_time.c":      VIOLATIONS_COM004_TIME,
        "src/safe_com004_urandom.c":         SAFE_COM004_URANDOM,
        "src/safe_com004_getrandom.c":       SAFE_COM004_GETRANDOM,
        # CBC-003 IV randomness
        "src/violations_cbc003_rand.c":      VIOLATIONS_CBC003_RAND,
        "src/violations_cbc003_const.c":     VIOLATIONS_CBC003_CONST,
        "src/safe_cbc003_csprng.c":          SAFE_CBC003_CSPRNG,
        # GCM-003 API order
        "src/violations_gcm003_counter.c":   VIOLATIONS_GCM003_COUNTER,
        "src/safe_gcm003_random.c":          SAFE_GCM003_RANDOM,
        # COM-003 hardcoded key
        "src/violations_com003_32byte.c":    VIOLATIONS_COM003_32BYTE,
        "src/safe_com003_derived.c":         SAFE_COM003_DERIVED,
        # CCM-005 zeroization
        "src/violations_ccm005_noclean.c":   VIOLATIONS_CCM005_NOCLEAN,
        "src/safe_ccm005_clean.c":           SAFE_CCM005_CLEAN,
        # GCM-005 zeroization
        "src/violations_gcm005_noclean.c":   VIOLATIONS_GCM005_NOCLEAN,
        "src/safe_gcm005_clean.c":           SAFE_GCM005_CLEAN,
        # CBC-004 zeroization
        "src/violations_cbc004_noclean.c":   VIOLATIONS_CBC004_NOCLEAN,
        "src/safe_cbc004_clean.c":           SAFE_CBC004_CLEAN,
        # CTR-003 nonce randomness
        "src/violations_ctr003_fixed.c":     VIOLATIONS_CTR003_FIXED,
        "src/safe_ctr003_random.c":          SAFE_CTR003_RANDOM,
        # CMAC-002 timing-safe comparison
        "src/violations_cmac002_memcmp.c":   VIOLATIONS_CMAC002_MEMCMP,
        "src/safe_cmac002_const.c":          SAFE_CMAC002_CONST,
        # COM-002 return value
        "src/violations_com002_nocheck.c":   VIOLATIONS_COM002_NOCHECK,
        "src/safe_com002_checked.c":         SAFE_COM002_CHECKED,
        # LEA-044 key scope
        "src/violations_lea044_leak.c":      VIOLATIONS_LEA044_LEAK,
        "src/safe_lea044_local.c":           SAFE_LEA044_LOCAL,
        # ECB-002 block check
        "src/violations_ecb002_nocheck2.c":  VIOLATIONS_ECB002_NOCHECK2,
        "src/safe_ecb002_checked2.c":        SAFE_ECB002_CHECKED2,
        # LEA-047 CTR MCT
        "src/violations_lea047_ctr2.c":      VIOLATIONS_LEA047_CTR2,
        "src/safe_lea047_ctr2.c":            SAFE_LEA047_CTR2,
    }

    with zipfile.ZipFile(OUT_PATH, "w", zipfile.ZIP_DEFLATED) as zout:
        # Copy all existing v11 entries, updating GROUND_TRUTH.md
        for name, data in v11_entries.items():
            if name == "GROUND_TRUTH.md":
                zout.writestr("GROUND_TRUTH.md", new_gt)
            else:
                zout.writestr(name, data)
        # Add all new C source files
        for name, content in new_files.items():
            zout.writestr(name, content)

    # Report counts
    lines = new_gt.splitlines()
    p_count = sum(1 for line in lines if "| P |" in line)
    n_count = sum(1 for line in lines if "| N |" in line)
    new_p   = sum(1 for line in NEW_GT_LINES.splitlines() if "| P |" in line)
    new_n   = sum(1 for line in NEW_GT_LINES.splitlines() if "| N |" in line)
    print(f"Created: {OUT_PATH}")
    print(f"New cases added : P={new_p}, N={new_n} ({new_p + new_n} total new)")
    print(f"Grand total     : P={p_count}, N={n_count}, total={p_count + n_count}")


if __name__ == "__main__":
    build_zip()
