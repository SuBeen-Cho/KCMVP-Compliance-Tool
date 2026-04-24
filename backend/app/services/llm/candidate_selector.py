"""L2 대상 선정 — 타입별 버킷 방식 + L1.5 이름 기반 사전 필터."""

import re
from typing import Any, Dict, List, Optional


# ─────────────────────────────────────────────────────────────────

# 변수명·함수명에 이 키워드가 포함되면 → FP 가능성 높음 → L2 스킵
_L15_FP_NAMES = frozenset({
    "sbox", "s_box", "delta", "lookup", "lut", "table",
    "test", "kat", "vector", "sample", "example",
    "round_const", "rcon", "permut", "mds", "mask",
    "rand_index", "rand_count", "rand_loop", "random_index",
})

# 변수명·함수명에 이 키워드가 포함되면 → TP 가능성 높음 → L2 강제 포함
_L15_TP_NAMES = frozenset({
    "key", "iv", "nonce", "secret", "priv", "master",
    "session_key", "encrypt_key", "aes_key", "des_key", "lea_key",
})


def _l15_name_filter(violation: Dict[str, Any]) -> Optional[bool]:
    """
    L1.5 이름 기반 필터.
    반환값:
      True  → TP 확실 → L2 강제 포함
      False → FP 확실 → L2 제외
      None  → 판단 불가 → 기존 로직대로
    """
    snippet = (violation.get("snippet") or "").lower()
    if not snippet:
        return None

    # 변수명 추출 (배열·포인터 선언 패턴)
    name_match = re.search(r'\b(\w+)\s*[\[=(*]', snippet)
    var_name = name_match.group(1).lower() if name_match else ""

    # TP 우선 판정
    if any(kw in var_name for kw in _L15_TP_NAMES):
        return True

    # FP 판정
    if any(kw in var_name or kw in snippet[:150] for kw in _L15_FP_NAMES):
        return False

    return None


# ─────────────────────────────────────────────────────────────────
# L2 대상 선정
# ─────────────────────────────────────────────────────────────────
def _select_l2_candidates(
    l1_violations: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    L2 판정 대상 선정 — 타입별 버킷 방식 + 위반 수에 따른 동적 cap.

    위반 총 수(N)에 따른 전체 상한:
      N ≤ 30  → 전체 심사 (cap = N)
      N ≤ 80  → cap = 60 (기본)
      N > 80  → cap = min(100, N // 2)  (대형 프로젝트 절반)

    버킷 비율:
      버킷 1 (ast):       cap의 42%, rule당 5건  ← 알고리즘 구조 위반 우선
      버킷 2 (high sev):  cap의 42%, rule당 8건  ← regex/semantic 고위험
      버킷 3 (기타):       cap의 16%, rule당 4건  ← medium/low
    """
    n_total = len(l1_violations)
    if n_total <= 30:
        total_cap = n_total
    elif n_total <= 80:
        total_cap = 80           # Phase 2: 60 → 80
    else:
        total_cap = min(150, n_total * 2 // 3)  # Phase 2: min(100,N//2) → min(150,2N/3)

    b1_cap = max(8,  int(total_cap * 0.50))  # Phase 2: ast 비중 0.42 → 0.50
    b2_cap = max(8,  int(total_cap * 0.35))  # Phase 2: high 비중 0.42 → 0.35
    b3_cap = max(4,  total_cap - b1_cap - b2_cap)
    needs_l2 = {"ast", "regex", "semantic"}
    # L1.5: 이름 기반 사전 필터 적용
    forced_in: List[Dict[str, Any]] = []
    forced_out_ids: set = set()
    for v in l1_violations:
        verdict = _l15_name_filter(v)
        if verdict is True:
            forced_in.append(v)
        elif verdict is False:
            forced_out_ids.add(id(v))
    forced_in_ids = {id(v) for v in forced_in}

    # Strategy F: needs_ai_review=True인 위반을 L2 대상에 포함
    # 단, missing 타입은 L2를 거치지 않고 직접 위반 확정 (L2 비결정성 방지)
    # missing 규칙은 패턴 부재 = 즉시 위반 확정이므로 AI 재판정 불필요
    eligible = [
        v for v in l1_violations
        if (v.get("pattern_type") in needs_l2
            or (v.get("needs_ai_review") and v.get("pattern_type") != "missing"))
        and id(v) not in forced_out_ids
    ]
    print(f"[L1.5] 강제포함={len(forced_in)}건, 강제제외={len(forced_out_ids)}건")

    severity_rank = {"high": 0, "medium": 1, "low": 2}

    def _fill_bucket(
        pool: List[Dict[str, Any]],
        max_items: int,
        per_rule_max: int,
        sort_key=None,
    ) -> List[Dict[str, Any]]:
        if sort_key is None:
            sort_key = lambda v: severity_rank.get(v.get("severity", "low"), 2)
        sorted_pool = sorted(pool, key=sort_key)
        per_rule: Dict[str, int] = {}
        bucket: List[Dict[str, Any]] = []
        for v in sorted_pool:
            rid = v.get("rule_id") or ""
            per_rule[rid] = per_rule.get(rid, 0) + 1
            if per_rule[rid] <= per_rule_max:
                bucket.append(v)
            if len(bucket) >= max_items:
                break
        return bucket

    # 버킷 1: ast 타입 — fallback 위반(confidence="후보") 우선, 이후 severity 순
    # [Priority 5] fallback-only 규칙 위반은 AI 재판정 필수 → cap 초과 시 먼저 검토받도록
    ast_pool = [v for v in eligible if v.get("pattern_type") == "ast"]
    ast_fallback_count = sum(1 for v in ast_pool if v.get("confidence") == "후보")
    bucket_ast = _fill_bucket(
        ast_pool,
        max_items=b1_cap,
        per_rule_max=10,
        sort_key=lambda v: (
            0 if v.get("confidence") == "후보" else 1,   # fallback 먼저
            severity_rank.get(v.get("severity", "low"), 2),
        ),
    )
    selected_keys = {id(v) for v in bucket_ast}

    # 버킷 2: high severity regex/semantic (missing 제외 — missing은 L2 미전송)
    high_pool = [
        v for v in eligible
        if id(v) not in selected_keys
        and v.get("pattern_type") in ("regex", "semantic")
        and v.get("severity") == "high"
    ]
    bucket_high = _fill_bucket(high_pool, max_items=b2_cap, per_rule_max=8)
    selected_keys.update(id(v) for v in bucket_high)

    # 버킷 3: 나머지
    other_pool = [v for v in eligible if id(v) not in selected_keys]
    bucket_other = _fill_bucket(other_pool, max_items=b3_cap, per_rule_max=4)

    result = bucket_ast + bucket_high + bucket_other
    ast_fb_in_bucket = sum(1 for v in bucket_ast if v.get("confidence") == "후보")
    print(
        f"[L2] 대상 선정: N={n_total}, cap={total_cap}, "
        f"ast={len(bucket_ast)}(fallback={ast_fb_in_bucket}/{ast_fallback_count}), "
        f"high={len(bucket_high)}, other={len(bucket_other)}, 합계={len(result)}건"
    )
    return result
