---
item_id: AS09.29
rule_id: COM-005
title: 온라인 API 호출 순서 (init→update→final)
kcmvp_ref: "블록암호 LEA 소스코드 사용 매뉴얼(v1.0) §4.3.12~§4.3.15"
severity: high
---

## 개요

대용량 데이터의 스트리밍 처리 시 온라인 API는 반드시
`lea_online_init` → `lea_online_update`(0회 이상) → `lea_online_final` 순서로 호출해야 한다.

## 요구사항

1. `lea_online_init`은 `lea_online_update` 호출 전에 반드시 실행해야 한다.
2. `lea_online_final`은 모든 `lea_online_update` 완료 후 반드시 호출해야 한다.
3. 예외/오류 경로에서도 `lea_online_final`이 호출되어야 SSP가 제로화된다.
4. 한 번 `final`이 호출된 ctx는 재사용 전에 반드시 `init`을 다시 호출해야 한다.

## 위반 패턴

```c
// ❌ init 없이 update 호출
int bad_stream(LEA_ONLINE_CTX *ctx, const uint8_t *data, size_t len, uint8_t *out) {
    lea_online_update(ctx, data, len, out);  // ctx 초기화 안 됨
    lea_online_final(ctx, out);
    return 0;
}

// ❌ final 없이 종료 (SSP 잔존)
int bad_stream_no_final(const uint8_t *key, const uint8_t *data, size_t len, uint8_t *out) {
    LEA_ONLINE_CTX ctx;
    lea_online_init(&ctx, key, 16);
    lea_online_update(&ctx, data, len, out);
    return 0;  // final 없음 → ctx에 SSP 잔존
}
```

## 올바른 구현

```c
// ✅ 올바른 순서 + 에러 처리 포함
int good_stream(const uint8_t *key, const uint8_t *data, size_t len, uint8_t *out) {
    LEA_ONLINE_CTX ctx;
    int ret;

    ret = lea_online_init(&ctx, key, 16);
    if (ret != 0) goto cleanup;

    ret = lea_online_update(&ctx, data, len, out);
    if (ret != 0) goto cleanup;

    ret = lea_online_final(&ctx, out);

cleanup:
    // 오류 경로에서도 ctx 제로화 보장
    if (ret != 0) {
        memset_s(&ctx, sizeof(ctx), 0, sizeof(ctx));
    }
    return ret;
}
```

## 참고

- LEA 매뉴얼 §4.3.12: "lea_online_init()으로 초기화 후 lea_online_update()를 반복 호출,
  마지막에 lea_online_final()을 호출하여 남은 데이터를 처리하고 내부 상태를 제거한다."
