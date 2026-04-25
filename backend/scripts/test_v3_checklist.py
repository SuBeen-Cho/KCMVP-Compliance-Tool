#!/usr/bin/env python3
"""
v3 GPTScan 체크리스트 프롬프트 효과 실측
===========================================
BEFORE: v2 AFTER (GCFS=True + key_lifecycle=True + 구 서술형 프롬프트)
        → l3_ba_checkpoint.json 의 after 결과 재사용
AFTER:  v3 (GCFS=True + key_lifecycle=True + GPTScan 체크리스트 프롬프트)
        → LEA-031, LEA-034, OFB-002, CFB-002 재실행

다른 규칙들은 프롬프트 변경 없으므로 BEFORE 결과를 그대로 복사.
"""
import sys, os, json, pathlib, copy, time, signal
from typing import Dict, Any, List, Optional

ROOT = pathlib.Path(os.getcwd())
sys.path.insert(0, str(ROOT))

for line in open('.env').readlines():
    if '=' in line and not line.strip().startswith('#'):
        k, _, v = line.strip().partition('=')
        os.environ.setdefault(k.strip(), v.strip())

# GPTScan으로 프롬프트가 변경된 4개 규칙
CHECKLIST_RULES = {"LEA-031", "LEA-034", "OFB-002", "CFB-002"}

V3_CHECKPOINT = ROOT / 'scripts' / 'l3_v3_checkpoint.json'
V3_RESULT_FILE = ROOT / 'scripts' / 'l3_v3_result.json'
V2_CHECKPOINT  = ROOT / 'scripts' / 'l3_ba_checkpoint.json'

print("=" * 70)
print("  v3 GPTScan 체크리스트 효과 실측")
print(f"  대상 규칙: {', '.join(sorted(CHECKLIST_RULES))}")
print("=" * 70)

# ── 1. v2 AFTER 결과 로드 (BEFORE로 사용) ─────────────────────────────
if not V2_CHECKPOINT.exists():
    print("❌ v2 체크포인트 없음 — test_l3_before_after.py 먼저 실행 필요")
    sys.exit(1)

v2_data   = json.loads(V2_CHECKPOINT.read_text())
v2_before = v2_data.get('before', [])
v2_after  = v2_data.get('after',  [])
job_name  = v2_data.get('job', '?')

if len(v2_after) < 30:
    print("❌ v2 AFTER 결과 불충분"); sys.exit(1)

print(f"  v2 Job: {job_name[:24]}...")
print(f"  v2 AFTER 로드: {len(v2_after)}건 (GPTScan BEFORE로 사용)")

# 4개 타깃 규칙의 v2 AFTER 현황
for r in sorted(CHECKLIST_RULES):
    items = [x for x in v2_after if x.get('rule_id') == r]
    t = sum(1 for x in items if x.get('is_real_issue') is True)
    f = sum(1 for x in items if x.get('is_real_issue') is False)
    n = sum(1 for x in items if x.get('is_real_issue') is None)
    print(f"    {r}: {len(items)}건 (T={t} F={f} N={n})")

# ── 2. 서비스 로드 ────────────────────────────────────────────────────
import app.services.llm_service as llm_svc
from app.services.llm_service import (
    _select_l3_candidates, _build_global_flow_summary,
    _build_structured_evidence, _get_code_context,
    _build_single_prompt, _call_gemini_with_retry,
    _fetch_guideline_text, _HIGH_ISOLATION_RULES,
)

# ── 3. Job 로드 ───────────────────────────────────────────────────────
jobs_dir = ROOT / 'storage' / 'jobs'
target_job = None
for j in sorted(jobs_dir.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
    if j.name.startswith(job_name[:8]):
        sgf = j/'symbol_graph.json'; vf = j/'violations.json'; prf = j/'preprocess_result.json'
        if sgf.exists() and vf.exists() and prf.exists():
            target_job = j
            break

if not target_job:
    # fallback: 최신 대형 job
    for j in sorted(jobs_dir.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
        sgf = j/'symbol_graph.json'; vf = j/'violations.json'; prf = j/'preprocess_result.json'
        if not (sgf.exists() and vf.exists() and prf.exists()):
            continue
        sg_   = json.loads(sgf.read_text())
        vdata_= json.loads(vf.read_text())
        if len(sg_.get('definitions', {})) >= 60 and len(vdata_) > 50:
            target_job = j; break

if not target_job:
    print("❌ 적합한 job 없음"); sys.exit(1)

vdata      = json.loads((target_job / 'violations.json').read_text())
sg         = json.loads((target_job / 'symbol_graph.json').read_text())
pre_result = json.loads((target_job / 'preprocess_result.json').read_text())
candidates = _select_l3_candidates(vdata)
gcfs       = _build_global_flow_summary(sg, pre_result)

print(f"\n  Job: {target_job.name[:24]}...")
print(f"  violations={len(vdata)}, L3 후보={len(candidates)}건")
print(f"  GCFS: {len(gcfs.splitlines())}줄")

# ── 4. 파일 컨텐츠 캐시 ──────────────────────────────────────────────
files = pre_result.get('files', [])
file_cache: Dict[str, str] = {}

def get_file_content(path: str) -> Optional[str]:
    if path in file_cache:
        return file_cache[path]
    for item in files:
        ip = item.get('path', '')
        if ip == path or ip.endswith(path) or path.endswith(ip):
            lines = item.get('lines')
            if lines:
                content = '\n'.join(lines)
                file_cache[path] = content
                return content
    return None

# ── 5. 판정 함수 (GCFS + key_lifecycle 항상 ON) ───────────────────────
def judge_single(violation: Dict, timeout_sec: int = 30) -> Dict:
    v = copy.deepcopy(violation)
    file_path = v.get('file') or v.get('file_path') or ''
    raw_line  = v.get('line')
    line      = int(raw_line) if raw_line else None
    pattern   = v.get('pattern_type') or 'regex'
    rule_id   = v.get('rule_id') or 'UNKNOWN'

    content = get_file_content(file_path)
    if not content and file_path:
        return {'is_real_issue': None, 'confidence': None, 'reasoning': '파일 없음'}

    code_block = ''
    if content:
        code_block = _get_code_context(content, line, pattern, violation=v, symbol_graph=sg)
    if not code_block:
        code_block = f"파일: {file_path}, 라인: {line}\n위반: {v.get('message','')}"

    ev = _build_structured_evidence(v, sg)
    if ev:
        code_block = ev + code_block

    if rule_id == 'COM-001' and v.get('key_lifecycle'):
        lc = ('=== 키 생명주기 분석 ===\n' + v['key_lifecycle'] + '\n' + '='*40 + '\n\n')
        code_block = lc + code_block

    is_doc = rule_id.startswith('DOC')
    if not is_doc:
        code_block = gcfs + code_block

    guideline = _fetch_guideline_text(rule_id)
    use_cot   = rule_id in _HIGH_ISOLATION_RULES
    prompt    = _build_single_prompt(file_path, v, code_block, guideline_text=guideline, use_cot=use_cot)

    try:
        def _handler(signum, frame): raise TimeoutError()
        signal.signal(signal.SIGALRM, _handler)
        signal.alarm(timeout_sec)
        obj = _call_gemini_with_retry(prompt)
        signal.alarm(0)
    except TimeoutError:
        return {'is_real_issue': None, 'confidence': None, 'reasoning': f'TIMEOUT({timeout_sec}s)'}
    except Exception as e:
        return {'is_real_issue': None, 'confidence': None, 'reasoning': f'ERR:{str(e)[:60]}'}

    if not obj:
        return {'is_real_issue': None, 'confidence': None, 'reasoning': 'Gemini 응답 없음'}
    return {
        'is_real_issue': obj.get('is_real_issue'),
        'confidence':    obj.get('confidence'),
        'reasoning':     (obj.get('reasoning') or obj.get('reason') or '')[:200],
    }

# ── 6. v3 AFTER 실행 (4개 규칙만 재실행, 나머지는 v2 AFTER 복사) ──────
checkpoint = {}
if V3_CHECKPOINT.exists():
    try:
        checkpoint = json.loads(V3_CHECKPOINT.read_text())
        print(f"\n  v3 체크포인트 로드: {len(checkpoint.get('after_new',[]))}건")
    except Exception:
        checkpoint = {}

after_new_done = checkpoint.get('after_new', [])  # {idx, rule_id, ...}

def save_v3_checkpoint():
    V3_CHECKPOINT.write_text(json.dumps(
        {'job': target_job.name, 'after_new': after_new_done},
        ensure_ascii=False, indent=2
    ))

# 4개 규칙에 해당하는 candidates 인덱스 수집
target_indices = [(i, v) for i, v in enumerate(candidates)
                  if v.get('rule_id') in CHECKLIST_RULES]
done_indices   = {x['idx'] for x in after_new_done}
remaining      = [(i, v) for i, v in target_indices if i not in done_indices]

print(f"\n[v3 AFTER] 체크리스트 대상: {len(target_indices)}건, 미완료: {len(remaining)}건")
if len(target_indices) == 0:
    print("  ※ L3 후보에 4개 규칙 없음 — 현재 job에 해당 위반 미발생 가능")

for i, v in remaining:
    rid = v.get('rule_id', '?')
    fp  = str(v.get('file', ''))[:28]
    print(f"  V3[{len(after_new_done)+1:3d}/{len(target_indices)}] {rid:13s} | {fp:<28} ", end='', flush=True)
    t0 = time.time()
    r  = judge_single(v)
    elapsed = time.time() - t0
    print(f"→ {str(r['is_real_issue']):5s} conf={str(r['confidence']):5s} ({elapsed:.1f}s)")
    after_new_done.append({'idx': i, 'rule_id': rid, 'file': str(v.get('file','')), **r})
    if len(after_new_done) % 5 == 0:
        save_v3_checkpoint()
    time.sleep(0.8)

save_v3_checkpoint()
print(f"\n  v3 재실행 완료: {len(after_new_done)}건")

# ── 7. v3 AFTER 전체 조립 (재실행분 + v2 나머지 복사) ─────────────────
after_new_by_idx = {x['idx']: x for x in after_new_done}
v3_after = []
for i, v in enumerate(candidates):
    rid = v.get('rule_id', '?')
    if i in after_new_by_idx:
        entry = after_new_by_idx[i]
        v3_after.append({
            'rule_id': rid, 'file': str(v.get('file', '')),
            'key_lifecycle': bool(v.get('key_lifecycle')),
            'is_real_issue': entry.get('is_real_issue'),
            'confidence':    entry.get('confidence'),
            'reasoning':     entry.get('reasoning', ''),
        })
    else:
        # v2 AFTER 결과 복사 (프롬프트 미변경 규칙)
        if i < len(v2_after):
            v3_after.append(v2_after[i])
        else:
            v3_after.append({
                'rule_id': rid, 'file': str(v.get('file', '')),
                'is_real_issue': None, 'confidence': None, 'reasoning': 'v2 AFTER 없음'
            })

# ── 8. 비교 분석 ──────────────────────────────────────────────────────
print("\n" + "=" * 70)
print("  결과 비교 (BEFORE=v2 AFTER, AFTER=v3 체크리스트)")
print("=" * 70)

N = min(len(v2_after), len(v3_after))
before_r = v2_after[:N]
after_r  = v3_after[:N]

b_true  = sum(1 for x in before_r if x.get('is_real_issue') is True)
b_false = sum(1 for x in before_r if x.get('is_real_issue') is False)
b_none  = sum(1 for x in before_r if x.get('is_real_issue') is None)
a_true  = sum(1 for x in after_r  if x.get('is_real_issue') is True)
a_false = sum(1 for x in after_r  if x.get('is_real_issue') is False)
a_none  = sum(1 for x in after_r  if x.get('is_real_issue') is None)

print(f"\n  {'지표':<35} {'BEFORE(v2)':>10} {'AFTER(v3)':>10} {'변화':>10}")
print(f"  {'-'*65}")
print(f"  {'총 비교 건수':<35} {N:>10}")
print(f"  {'is_real=True  (진짜 위반)':<35} {b_true:>10} {a_true:>10} {a_true-b_true:>+10}")
print(f"  {'is_real=False (FP 제거)':<35} {b_false:>10} {a_false:>10} {a_false-b_false:>+10}")
print(f"  {'판정 불가 (None)':<35} {b_none:>10} {a_none:>10} {a_none-b_none:>+10}")
print(f"  {'FP 제거율':<35} {b_false/N*100:>9.1f}% {a_false/N*100:>9.1f}%  {(a_false-b_false)/N*100:>+8.1f}%p")

flips    = [(b, a) for b, a in zip(before_r, after_r)
            if b.get('is_real_issue') != a.get('is_real_issue')]
flip_T2F = [(b,a) for b,a in flips if b.get('is_real_issue') is True  and a.get('is_real_issue') is False]
flip_F2T = [(b,a) for b,a in flips if b.get('is_real_issue') is False and a.get('is_real_issue') is True]
flip_N   = [(b,a) for b,a in flips if None in (b.get('is_real_issue'), a.get('is_real_issue'))]

print(f"\n  판정 번복 총 {len(flips)}건 / {N}건 ({len(flips)/N*100:.1f}%)")
print(f"    True→False (v3가 FP 추가 제거): {len(flip_T2F)}건")
print(f"    False→True (v3가 FN 복구):      {len(flip_F2T)}건")
print(f"    None 관련:                       {len(flip_N)}건")

# 4개 체크리스트 규칙만 상세 분석
print(f"\n  [체크리스트 대상 4개 규칙 상세]")
from collections import defaultdict
for rule in sorted(CHECKLIST_RULES):
    b_items = [x for x in before_r if x.get('rule_id') == rule]
    a_items = [x for x in after_r  if x.get('rule_id') == rule]
    bt = sum(1 for x in b_items if x.get('is_real_issue') is True)
    bf = sum(1 for x in b_items if x.get('is_real_issue') is False)
    bn = sum(1 for x in b_items if x.get('is_real_issue') is None)
    at_ = sum(1 for x in a_items if x.get('is_real_issue') is True)
    af = sum(1 for x in a_items if x.get('is_real_issue') is False)
    an = sum(1 for x in a_items if x.get('is_real_issue') is None)
    changed = "🔄" if (bt != at_ or bf != af) else "  "
    print(f"  {changed} {rule:<13}: BEFORE {bt}T/{bf}F/{bn}N → AFTER {at_}T/{af}F/{an}N")

    # 번복된 항목 출력
    if b_items and a_items:
        for b, a in zip(b_items, a_items):
            if b.get('is_real_issue') != a.get('is_real_issue'):
                fp = str(b.get('file',''))[-25:]
                print(f"       번복: {b.get('is_real_issue')} → {a.get('is_real_issue')}  ({fp})")

# confidence 변화 (체크리스트 규칙만, T→T)
conf_changes = []
for b, a in zip(before_r, after_r):
    if b.get('rule_id') not in CHECKLIST_RULES:
        continue
    if b.get('is_real_issue') is True and a.get('is_real_issue') is True:
        try:
            bc = int(b.get('confidence', 0) or 0)
            ac = int(a.get('confidence', 0) or 0)
            if bc > 0 and ac > 0:
                conf_changes.append((b.get('rule_id'), bc, ac))
        except (TypeError, ValueError):
            pass

if conf_changes:
    avg_b = sum(c[1] for c in conf_changes) / len(conf_changes)
    avg_a = sum(c[2] for c in conf_changes) / len(conf_changes)
    print(f"\n  [confidence — 체크리스트 규칙 T→T {len(conf_changes)}건]")
    print(f"    BEFORE: {avg_b:.1f}  →  AFTER: {avg_a:.1f}  (diff: {avg_a-avg_b:+.1f})")

# 결과 저장
result = {
    'description': 'v3 GPTScan 체크리스트 효과 측정 (BEFORE=v2 AFTER, AFTER=v3)',
    'checklist_rules': sorted(CHECKLIST_RULES),
    'job': target_job.name,
    'total': N,
    'before': {'true': b_true, 'false': b_false, 'none': b_none},
    'after':  {'true': a_true, 'false': a_false, 'none': a_none},
    'flips':  {'T2F': len(flip_T2F), 'F2T': len(flip_F2T), 'total': len(flips)},
    'per_rule': {},
}
for rule in sorted(CHECKLIST_RULES):
    b_items = [x for x in before_r if x.get('rule_id') == rule]
    a_items = [x for x in after_r  if x.get('rule_id') == rule]
    result['per_rule'][rule] = {
        'before': {
            'true':  sum(1 for x in b_items if x.get('is_real_issue') is True),
            'false': sum(1 for x in b_items if x.get('is_real_issue') is False),
            'none':  sum(1 for x in b_items if x.get('is_real_issue') is None),
        },
        'after': {
            'true':  sum(1 for x in a_items if x.get('is_real_issue') is True),
            'false': sum(1 for x in a_items if x.get('is_real_issue') is False),
            'none':  sum(1 for x in a_items if x.get('is_real_issue') is None),
        },
    }

V3_RESULT_FILE.write_text(json.dumps(result, ensure_ascii=False, indent=2))

print("\n" + "=" * 70)
print("  핵심 수치 (v3 체크리스트 효과)")
print("=" * 70)
print(f"  체크리스트 적용 규칙: {', '.join(sorted(CHECKLIST_RULES))}")
print(f"  재실행 건수: {len(target_indices)}건 (나머지 {N-len(target_indices)}건은 v2 결과 복사)")
print(f"  전체 FP 변화: {b_false}건 → {a_false}건 ({a_false-b_false:+d}건)")
print(f"  전체 판정 번복: {len(flips)}건 ({len(flips)/N*100:.1f}%)")
print(f"    True→False: {len(flip_T2F)}건  /  False→True: {len(flip_F2T)}건")
if conf_changes:
    print(f"  confidence(T→T 체크리스트): BEFORE {avg_b:.1f} → AFTER {avg_a:.1f} ({avg_a-avg_b:+.1f}점)")
print(f"  결과: scripts/l3_v3_result.json")
print("=" * 70)
