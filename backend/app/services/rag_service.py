"""
RAGService (L3): 가이드라인 문서 검색 + 위반 근거 추출.

검색 전략 (3단계 우선순위):
  1. Direct-RAG: mapping_service로 guideline MD 파일 직접 조회 (가장 정확)
  2. Keyword Search: guidelines/ 폴더 전체에서 TF-IDF 유사도 검색 (fallback)
  3. ChromaDB: 벡터 임베딩 검색 (선택적, chromadb 설치 시 활성화)

ChromaDB 활성화 방법:
  pip install chromadb sentence-transformers
  환경변수 RAG_USE_CHROMA=true 설정
"""

import hashlib
import json
import math
import os
import re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from app.services.mapping_service import (
    get_guideline_path,
    get_search_query,
    lookup,
)
from app.services.rag_grounding import (
    _verified_rule_binding,
    normalize_evidence_bundle,
    render_evidence_bundle,
    route_rag,
)
from app.services.analysis_stage_contract import stamp


def rag_ablation_disabled() -> bool:
    """True only for controlled L2 ablation experiments."""
    return os.environ.get("ABLATION_NO_RAG", "0") == "1"
from app.config import settings

# 실제 지식 DB 폴더들 (프로젝트 루트 기준)
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
_DB_DIRS = [
    _PROJECT_ROOT / "ruleset" / "docs",   # 설계서/형상관리/시험서 가이드라인 DB
    _PROJECT_ROOT / "ruleset" / "LEA",    # LEA 알고리즘 DB
    _PROJECT_ROOT / "backend" / "guidelines",  # 기존 guidelines (fallback 보조)
]
# 하위 호환 단일 경로 (기존 코드 참조용)
_GUIDELINES_DIR = _PROJECT_ROOT / "backend" / "guidelines"

# ChromaDB 활성화 여부 (settings 또는 환경변수로 제어)
_USE_CHROMA = settings.RAG_USE_CHROMA or os.environ.get("RAG_USE_CHROMA", "false").lower() == "true"
_chroma_collection = None

# ChromaDB 보강 검색 캐시 (rule_id → List[Dict]) — 동일 룰 중복 쿼리 방지
_chroma_boost_cache: Dict[str, List[Dict[str, Any]]] = {}

_EVIDENCE_AUDIT = _PROJECT_ROOT / "backend" / "mapping" / "rule_evidence_audit.json"
_DEFAULT_OFFICIAL_INDEX = _PROJECT_ROOT / "backend" / "data" / "evidence" / "official_units.local.json"
_official_index_cache: Dict[str, Any] = {}


def _official_index_path() -> Path:
    configured = os.environ.get("KCMVP_OFFICIAL_EVIDENCE_INDEX", "").strip()
    return Path(configured).resolve() if configured else _DEFAULT_OFFICIAL_INDEX


def _load_verified_official_units(rule_id: str) -> List[Dict[str, Any]]:
    """Load only the sealed units explicitly verified for ``rule_id``."""
    try:
        audit = json.loads(_EVIDENCE_AUDIT.read_text(encoding="utf-8"))
        row = (audit.get("rules") or {}).get(rule_id) or {}
        if row.get("status") != "verified":
            return []
        expected_ids = list(row.get("evidence_unit_ids") or [])
        if not expected_ids:
            return []
        path = _official_index_path()
        stat = path.stat()
        cache_key = f"{path}:{stat.st_mtime_ns}:{stat.st_size}"
        cached = _official_index_cache.get(cache_key)
        if cached is None:
            payload = json.loads(path.read_text(encoding="utf-8"))
            if payload.get("schema_version") != "1.0" or payload.get("collection") != "official_source":
                return []
            units, sources = payload.get("units"), payload.get("sources")
            if not isinstance(units, list) or not isinstance(sources, list):
                return []
            source_hashes = {str(s.get("source_id")): str(s.get("sha256")) for s in sources}
            by_id: Dict[str, Dict[str, Any]] = {}
            for unit in units:
                if not isinstance(unit, dict) or not isinstance(unit.get("text"), str):
                    return []
                text = unit["text"]
                if hashlib.sha256(text.encode("utf-8")).hexdigest() != unit.get("text_sha256"):
                    return []
                by_id[str(unit.get("unit_id"))] = unit
            cached = {"by_id": by_id, "source_hashes": source_hashes}
            _official_index_cache.clear()
            _official_index_cache[cache_key] = cached
        locator = row.get("source_locator") or {}
        source_id = str(locator.get("source_id") or "")
        if cached["source_hashes"].get(source_id) != row.get("source_sha256"):
            return []
        selected = [cached["by_id"].get(unit_id) for unit_id in expected_ids]
        if any(unit is None or unit.get("source_id") != source_id for unit in selected):
            return []
        # Trust status is attached only after registry/source/text verification;
        # the serialized index itself cannot self-assert this field.
        return [
            dict(unit, status="verified", source_sha256=row["source_sha256"])
            for unit in selected if unit is not None
        ]
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return []


# ─────────────────────────────────────────────────────────────────
# 1. Direct-RAG: guideline MD 파일 직접 로드
# ─────────────────────────────────────────────────────────────────
def _load_guideline_file(
    rule_id: str, *, allow_unverified_legacy: bool = False
) -> Optional[str]:
    """저자 작성 guideline은 명시적 legacy opt-in에서만 반환한다."""
    path = get_guideline_path(
        rule_id, allow_unverified_legacy=allow_unverified_legacy
    )
    if path and path.exists():
        return path.read_text(encoding="utf-8")
    return None


def _extract_sections_from_md(content: str) -> List[Dict[str, str]]:
    """
    MD 파일에서 섹션(## 제목) 단위로 분리.
    YAML frontmatter (--- ... ---) 는 건너뜀.
    반환: [{"title": "개요", "content": "..."}, ...]
    """
    lines = content.splitlines()

    # frontmatter 건너뛰기
    start = 0
    if lines and lines[0].strip() == "---":
        for i, line in enumerate(lines[1:], 1):
            if line.strip() == "---":
                start = i + 1
                break

    sections = []
    # ``##``가 없는 짧은 author guideline도 검색 가능한 하나의 문서 청크로
    # 보존한다. 첫 ``#`` 제목은 그 청크의 provenance-friendly title로 쓴다.
    document_title = "본문"
    current_title = document_title
    current_lines: List[str] = []

    for line in lines[start:]:
        if line.startswith("## "):
            if current_lines:
                sections.append({
                    "title": current_title,
                    "content": "\n".join(current_lines).strip(),
                })
            current_title = line[3:].strip()
            current_lines = []
        elif line.startswith("# "):
            document_title = line[2:].strip() or document_title
            if not current_lines and current_title == "본문":
                current_title = document_title
        else:
            current_lines.append(line)

    if current_lines:
        sections.append({
            "title": current_title,
            "content": "\n".join(current_lines).strip(),
        })

    return [s for s in sections if s["content"]]


# ─────────────────────────────────────────────────────────────────
# 2. Keyword Search: TF-IDF 기반 전체 guidelines 검색
# ─────────────────────────────────────────────────────────────────
_keyword_index: List[Dict[str, Any]] = []
_index_built = False


def _tokenize(text: str) -> List[str]:
    """한국어 + 영어 토큰 분리 (단어 단위)."""
    text = re.sub(r"[^\w가-힣]", " ", text)
    return [t.lower() for t in text.split() if len(t) > 1]


def _build_keyword_index() -> None:
    global _keyword_index, _index_built
    if _index_built:
        return
    _keyword_index = []

    # 실제 DB 폴더들을 모두 인덱싱
    md_paths = []
    for db_dir in _DB_DIRS:
        if db_dir.exists():
            md_paths.extend(sorted(db_dir.rglob("*.md")))
            md_paths.extend(sorted(db_dir.rglob("*.MD")))

    if not md_paths:
        _index_built = True
        print("[RAG] 경고: DB 폴더에 마크다운 파일 없음")
        return

    for md_path in md_paths:
        try:
            content = md_path.read_text(encoding="utf-8")
        except Exception:
            continue
        sections = _extract_sections_from_md(content)
        meta = _parse_frontmatter(content)
        # 짧은 author guideline은 frontmatter가 없을 수 있다. 안정적인 파일명
        # prefix(AES-001_...)에서 rule id만 복구해 keyword/vector provenance를
        # 보존한다.
        inferred_rule_id = ""
        if not meta.get("rule_id"):
            match = re.match(r"^([A-Za-z]+-\d+)(?:_|\.|$)", md_path.name)
            inferred_rule_id = match.group(1).upper() if match else ""
        # item_id가 리스트인 경우 처리 (예: ["AS03.01", "AS03.02"])
        raw_item_id = meta.get("item_id", "")
        if isinstance(raw_item_id, list):
            item_id_str = " ".join(raw_item_id)
        else:
            item_id_str = str(raw_item_id)
        for sec in sections:
            doc_text = f"{sec['title']} {sec['content']}"
            tokens = _tokenize(doc_text)
            _keyword_index.append({
                "path": str(md_path),
                "rule_id": meta.get("rule_id", "") or inferred_rule_id,
                "item_id": item_id_str,
                "title": sec["title"],
                "content": sec["content"],
                "tokens": tokens,
                "tf": Counter(tokens),
            })

    print(f"[RAG] 인덱스 구축 완료: {len(_keyword_index)}개 청크 ({len(md_paths)}개 파일)")
    _index_built = True


def _parse_frontmatter(content: str) -> Dict[str, str]:
    """YAML frontmatter (--- ... ---) 파싱."""
    meta: Dict[str, str] = {}
    lines = content.splitlines()
    if not lines or lines[0].strip() != "---":
        return meta
    for line in lines[1:]:
        if line.strip() == "---":
            break
        if ":" in line:
            k, _, v = line.partition(":")
            meta[k.strip()] = v.strip().strip('"')
    return meta


def _tfidf_search(query: str, top_k: int = 3) -> List[Dict[str, Any]]:
    """TF-IDF 기반 guideline 섹션 검색."""
    _build_keyword_index()
    if not _keyword_index:
        return []

    query_tokens = _tokenize(query)
    if not query_tokens:
        return []

    # IDF 계산
    n_docs = len(_keyword_index)
    df: Counter = Counter()
    for doc in _keyword_index:
        for t in set(doc["tokens"]):
            df[t] += 1

    def idf(t: str) -> float:
        return math.log((n_docs + 1) / (df.get(t, 0) + 1)) + 1

    # 각 문서에 대해 TF-IDF 점수 계산
    scores: List[Tuple[float, int]] = []
    for i, doc in enumerate(_keyword_index):
        score = 0.0
        doc_len = len(doc["tokens"]) or 1
        for t in query_tokens:
            tf_val = doc["tf"].get(t, 0) / doc_len
            score += tf_val * idf(t)
        if score > 0:
            scores.append((score, i))

    scores.sort(reverse=True)
    results = []
    for score, idx in scores[:top_k]:
        doc = _keyword_index[idx]
        results.append({
            "content": doc["content"],
            "title": doc["title"],
            "source": doc["path"],
            "rule_id": doc["rule_id"],
            "score": round(score, 4),
        })
    return results


# ─────────────────────────────────────────────────────────────────
# 3. ChromaDB (선택적)
# ─────────────────────────────────────────────────────────────────
def _get_chroma_collection():
    global _chroma_collection
    if _chroma_collection is not None:
        return _chroma_collection
    try:
        import chromadb
        from chromadb.utils import embedding_functions
        chroma_dir = Path(settings.CHROMA_PERSIST_DIR)
        chroma_dir.mkdir(parents=True, exist_ok=True)
        client = chromadb.PersistentClient(path=str(chroma_dir))
        _embed_model = settings.RAG_EMBEDDING_MODEL or "BAAI/bge-m3"
        print(f"[RAG] 임베딩 모델 로드: {_embed_model}")
        ef = embedding_functions.SentenceTransformerEmbeddingFunction(
            model_name=_embed_model
        )
        _chroma_collection = client.get_or_create_collection(
            "kcmvp_guidelines", embedding_function=ef
        )
        if _chroma_collection.count() == 0:
            _ingest_to_chroma(_chroma_collection)
        return _chroma_collection
    except ImportError:
        print("[RAG] chromadb/sentence-transformers 미설치 → keyword search 사용")
        return None
    except Exception as e:
        print(f"[RAG] ChromaDB 초기화 실패: {e}")
        return None


def _ingest_to_chroma(collection) -> None:
    """guidelines/ MD 파일을 ChromaDB에 적재."""
    _build_keyword_index()
    docs, metas, ids = [], [], []
    for i, doc in enumerate(_keyword_index):
        docs.append(f"{doc['title']}\n{doc['content']}")
        metas.append({
            "source": doc["path"],
            "rule_id": doc["rule_id"],
            "title": doc["title"],
        })
        ids.append(f"chunk_{i}")
    if docs:
        collection.add(documents=docs, metadatas=metas, ids=ids)
    print(f"[RAG] ChromaDB 적재 완료: {len(docs)}개 청크")


def _chroma_search(query: str, item_ids: List[str], top_k: int = 3) -> List[Dict[str, Any]]:
    """ChromaDB 벡터 검색."""
    col = _get_chroma_collection()
    if col is None:
        return []
    try:
        where = {"rule_id": {"$in": [r for r in item_ids]}} if item_ids else None
        results = col.query(
            query_texts=[query],
            where=where,
            n_results=top_k,
        )
        chunks = results.get("documents", [[]])[0]
        metas = results.get("metadatas", [[]])[0]
        return [
            {"content": c, "source": m.get("source", ""), "title": m.get("title", "")}
            for c, m in zip(chunks, metas)
        ]
    except Exception as e:
        print(f"[RAG] ChromaDB 검색 실패: {e}")
        return []


# ─────────────────────────────────────────────────────────────────
# 메인 API
# ─────────────────────────────────────────────────────────────────
def search_evidence(
    rule_id: str,
    query: Optional[str] = None,
    top_k: int = 3,
    *,
    allow_unverified_legacy: bool = False,
) -> List[Dict[str, Any]]:
    """
    rule_id 기반으로 가이드라인 근거 청크 검색.

    우선순위:
      1. Direct-RAG (guideline MD 직접 조회)
      2. ChromaDB (설치 + RAG_USE_CHROMA=true 시)
      3. TF-IDF 키워드 검색 (fallback)

    Parameters
    ----------
    rule_id  : KCMVP 룰 ID (예: "COM-001")
    query    : 추가 검색 쿼리 (없으면 mapping의 l3_search_query 사용)
    top_k    : 반환할 최대 청크 수

    Returns
    -------
    list[dict] : [{"content": ..., "title": ..., "source": ..., "score": ...}]
    """
    results: List[Dict[str, Any]] = []

    official = _load_verified_official_units(rule_id)
    if official:
        # The verified mapping is an audited evidence bundle, not a ranked
        # similarity result.  Returning only top_k could silently drop a table
        # row, direction, exception, or companion MOVS artifact requirement.
        return official

    # Author guideline Direct-RAG is a compatibility path, never official
    # evidence. The normal path is fail-closed and official units are loaded by
    # rag_grounding from the sealed official index.
    if not allow_unverified_legacy:
        return []

    guideline_content = _load_guideline_file(
        rule_id, allow_unverified_legacy=True
    )
    if guideline_content:
        sections = _extract_sections_from_md(guideline_content)
        # 핵심 섹션 우선 반환 — 부분 문자열 매칭 (새 DB 파일: "2. 상세 요구사항 (Requirements)" 등)
        priority_kw = {"요구사항", "보안요구사항", "올바른 구현", "위반 패턴", "해설", "증빙"}
        priority = [s for s in sections if any(kw in s["title"] for kw in priority_kw)]
        others   = [s for s in sections if not any(kw in s["title"] for kw in priority_kw)]
        ordered  = priority + others

        for sec in ordered[:top_k]:
            results.append({
                "content": sec["content"],
                "title": sec["title"],
                "source": f"guidelines/{rule_id}",
                "rule_id": rule_id,
                "score": 1.0,  # Direct-RAG는 최고 신뢰도
            })

    # Legacy opt-in이더라도 다른 규칙의 해설을 fallback으로 주입하지 않는다.
    search_q = query or get_search_query(rule_id)

    if results:
        # Direct-RAG 성공 → ChromaDB로 보강 (캐시 적용)
        if _USE_CHROMA:
            results = _boost_with_chroma(results, rule_id, search_q, top_k)
        return results

    return []


def _boost_with_chroma(
    direct_results: List[Dict[str, Any]],
    rule_id: str,
    search_q: str,
    top_k: int,
) -> List[Dict[str, Any]]:
    """
    Direct-RAG 결과를 ChromaDB 검색으로 보강.
    동일 rule_id 쿼리는 캐시에서 재사용하여 반복 임베딩 방지.
    Direct-RAG에 없는 source의 청크만 추가 (중복 제거).
    """
    global _chroma_boost_cache

    if rule_id not in _chroma_boost_cache:
        # rule_id 필터 없이 의미 기반 검색 → 다른 관련 문서에서 보강
        extra = _chroma_search(search_q, [], top_k=4)
        _chroma_boost_cache[rule_id] = extra
    else:
        extra = _chroma_boost_cache[rule_id]

    if not extra:
        return direct_results

    existing_sources = {r.get("source", "") for r in direct_results}
    added = 0
    for chunk in extra:
        src = chunk.get("source", "")
        # Direct-RAG와 동일 rule_id 파일이면 스킵
        rule_in_src = rule_id.lower().replace("-", "_") in src.lower().replace("-", "_")
        if not rule_in_src and src not in existing_sources and added < 2:
            direct_results.append(chunk)
            existing_sources.add(src)
            added += 1

    return direct_results[:top_k + 2]  # 최대 top_k+2까지 허용 (보강분 포함)


def extract_evidence_for_violation(
    violation_message: str,
    rule_id: str,
    top_k: int = 3,
) -> Optional[str]:
    """
    위반에 대한 공식 가이드라인 근거 문자열 반환.
    search_evidence의 결과를 하나의 텍스트로 합산.
    """
    chunks = search_evidence(rule_id, query=f"{rule_id} {violation_message}", top_k=top_k)
    if not chunks:
        return None

    parts = []
    for chunk in chunks:
        title = chunk.get("title", "")
        content = chunk.get("content", "")
        source = chunk.get("source", "")
        if title:
            parts.append(f"### {title}\n{content}")
        else:
            parts.append(content)

    result = "\n\n".join(parts)
    # 출처 정보 추가
    sources = {c.get("source", "") for c in chunks if c.get("source")}
    if sources:
        result += f"\n\n*출처: {', '.join(sorted(sources))}*"

    return result if result.strip() else None


def attach_evidence(
    violations: List[Dict[str, Any]],
    top_k: int = 2,
) -> List[Dict[str, Any]]:
    """
    위반 리스트 각 항목에 RAG 근거(evidence 필드)를 추가해 반환.

    Parameters
    ----------
    violations : post_process_violations 결과
    top_k      : 항목당 최대 근거 청크 수

    Returns
    -------
    list[dict] : evidence 필드가 추가된 위반 리스트 (원본 수정 없이 새 dict 반환)
    """
    if rag_ablation_disabled():
        return [dict(item, evidence="", rag_ablation=True) for item in violations]
    result = []
    for v in violations:
        item = dict(v)
        # 이미 evidence가 있으면 스킵
        if item.get("evidence"):
            result.append(item)
            continue

        rule_id = (item.get("rule_id") or "").strip()
        # L3 rule_id는 "L3-COM-001" 형식 → 원본 rule_id 추출
        if rule_id.startswith("L3-"):
            rule_id = rule_id[3:]

        msg = item.get("message") or ""
        try:
            evidence = extract_evidence_for_violation(msg, rule_id, top_k=top_k)
        except Exception as e:
            print(f"[RAG] evidence 첨부 실패 ({rule_id}): {e}")
            evidence = None

        if evidence:
            item["evidence"] = evidence
        result.append(item)
    return result


def run_l2_rag_context(violations: list, max_chars: int = 4000) -> list:
    """L2: RAG 기반 맥락 형성 — rule_id별 가이드라인 텍스트를 각 위반 객체에 주입.

    L1 위반 리스트를 받아 각 항목에 'rag_guideline_text' 필드를 추가한 뒤 반환.
    L3(LLM 판정)은 이 필드를 프롬프트에 직접 주입하여 가이드라인 문맥을 활용한다.
    """
    # 평가 조건 간 입력 오염을 막기 위해 호출자의 L1 후보를 변경하지 않는다.
    result = [dict(violation) for violation in violations]
    if rag_ablation_disabled():
        for violation in result:
            violation["rag_guideline_text"] = ""
            violation["rag_ablation"] = True
            violation["rag_route"] = {"decision": "skip", "reason": "controlled_ablation"}
            violation["rag_evidence_bundle"] = []
            stamp(violation, "hold", "controlled_ablation_no_official_evidence", "prohibited")
        return result
    guideline_cache: dict = {}
    bundle_cache: dict = {}
    retrieve_rule_ids = set()
    for violation in result:
        route = route_rag(violation)
        violation["rag_route"] = route
        if route["decision"] == "retrieve":
            retrieve_rule_ids.add(violation.get("rule_id") or "UNKNOWN")
    for rid in retrieve_rule_ids:
        try:
            chunks = search_evidence(rid, top_k=2)
            if chunks:
                bundle = normalize_evidence_bundle(chunks)
                bundle_cache[rid] = bundle
                guideline_cache[rid] = render_evidence_bundle(bundle, max_chars=max_chars)
            else:
                bundle_cache[rid] = []
                guideline_cache[rid] = ""
        except Exception as e:
            print(f"[L2][RAG] 가이드라인 fetch 실패 ({rid}): {e}")
            guideline_cache[rid] = ""

    loaded = sum(1 for g in guideline_cache.values() if g)
    skipped = sum(1 for v in result if v["rag_route"]["decision"] == "skip")
    deterministic = sum(
        1 for v in result
        if v["rag_route"]["decision"] == "deterministic_verified_rule"
    )
    print(
        f"[L2][RAG] evidence bundle 로드: {loaded}건 (/{len(guideline_cache)}), "
        f"router skip={skipped}, deterministic={deterministic}"
    )

    for v in result:
        rid = v.get("rule_id") or "UNKNOWN"
        if v["rag_route"]["decision"] == "retrieve":
            v["rag_guideline_text"] = guideline_cache.get(rid, "")
            v["rag_evidence_bundle"] = [dict(u) for u in bundle_cache.get(rid, [])]
            if not v["rag_evidence_bundle"]:
                v["rag_grounding_status"] = "evidence_absent"
                stamp(v, "hold", "official_evidence_absent", "prohibited",
                      history=["retrieval_required", "hold"])
            else:
                binding = _verified_rule_binding(str(rid).upper())
                if binding is None:
                    v["rag_guideline_text"] = ""
                    v["rag_evidence_bundle"] = []
                    v["rag_grounding_status"] = "rule_provenance_unavailable"
                    stamp(v, "hold", "rule_provenance_unavailable", "prohibited",
                          history=["retrieval_required", "hold"])
                    continue
                v["rule_provenance_sha256"] = binding["rule_provenance_sha256"]
                stamp(v, "ai_required", "retrieved_evidence_requires_contextual_judgment", "required",
                      history=["retrieval_required", "evidence_verified", "ai_required"])
        elif v["rag_route"]["decision"] == "deterministic_verified_rule":
            units = normalize_evidence_bundle(_load_verified_official_units(rid))
            if not units:
                # Registry/index drift revokes the optimization immediately.
                v["rag_route"] = {"decision": "retrieve", "reason": "deterministic_provenance_unavailable"}
                v["rag_guideline_text"] = ""
                v["rag_evidence_bundle"] = []
                v["rag_grounding_status"] = "evidence_absent"
                stamp(v, "hold", "deterministic_provenance_unavailable", "prohibited",
                      history=["deterministic", "retrieval_required", "hold"])
                continue
            v["rag_guideline_text"] = ""
            v["rag_evidence_bundle"] = [dict(unit) for unit in units]
            v["rag_grounding_status"] = "deterministic_official_evidence"
            v["decision_source"] = "deterministic_l1_official_evidence"
            v["official_evidence_provenance"] = [{
                "unit_id": unit["unit_id"],
                "source_id": unit["source_id"],
                "locator": dict(unit.get("locator") or {}),
                "span_sha256": unit["span_sha256"],
                "source_sha256": unit.get("source_sha256"),
            } for unit in units]
            v["llm_calls_avoided"] = 1
            stamp(v, "deterministic", "verified_literal_and_official_provenance", "not_required")
        else:
            v["rag_guideline_text"] = ""
            v["rag_evidence_bundle"] = []
            v["rag_grounding_status"] = "not_required"
            stamp(v, "deterministic", "deterministic_structural_evidence", "not_required")
        v.pop("rag_ablation", None)
    return result


def build_or_get_index(docs_dir: Path, persist_dir: str) -> None:
    """
    ChromaDB 인덱스 구축 (RAG_USE_CHROMA=true 시 호출).
    기존 stub과의 호환성 유지.
    """
    if _USE_CHROMA:
        _get_chroma_collection()
    else:
        _build_keyword_index()
        print(f"[RAG] Keyword index 구축: {len(_keyword_index)}개 청크")


def preload() -> None:
    """
    서버 시작 시 RAG 인덱스를 사전 로딩한다.

    - 키워드 인덱스는 항상 구축 (TF-IDF fallback 공통 사용)
    - RAG_USE_CHROMA=true 이면 ChromaDB + 임베딩 모델도 로드
    분석 요청 첫 번째 호출 시 3~6초 지연을 서버 시작 시점으로 이동.
    """
    _build_keyword_index()
    if _USE_CHROMA:
        _get_chroma_collection()
