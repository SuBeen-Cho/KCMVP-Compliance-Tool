"""
DocRuleService: 설계서/시험서/지침서 등 문서 제출물에 대한 L1 규칙 검사.

- 전처리된 문서 데이터(doc_preprocess_result)를 입력으로 받아
- DOC-xxx YAML 룰(design/config_mgmt/test)을 로드해
- 풀텍스트에 missing/regex/semantic 적용 후 위반 리스트 반환.

pattern_type 처리 정책:
  missing  : 패턴 미존재 → 즉시 위반 확정
  regex    : 패턴 발견 → 즉시 위반 확정 (발견 위치 ranges 포함)
  semantic : 패턴(키워드) 미존재 → L1 위반 후보 생성 + needs_ai_review=True 표시
             (추후 L3 AI가 연결되면 정밀 의미 판정으로 대체 예정)
"""

import re
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


def load_doc_rules(rules_dir: Path) -> List[Dict[str, Any]]:
    """rules/docs/ 아래 design.yaml, config_mgmt.yaml, test.yaml 을 로드해 룰 리스트 반환."""
    rules: List[Dict[str, Any]] = []
    docs_dir = rules_dir / "docs"
    if not docs_dir.is_dir():
        return rules
    for yaml_path in docs_dir.glob("*.yaml"):
        try:
            raw = yaml_path.read_text(encoding="utf-8")
            data = yaml.safe_load(raw) or {}
            rules.extend(data.get("rules", []))
        except Exception:
            continue
    return rules


def _build_fulltext(
    doc_preprocess_result: Dict[str, Any],
    doc_type_filter: Optional[str] = None,
) -> str:
    """
    sections[] 를 순회해 title + text + 표 name/headers 를 이어 붙인 풀텍스트 반환.
    doc_type_filter: design | config_mgmt | test. 전처리 결과의 scm 은 config_mgmt 로 간주.
    """
    sections = doc_preprocess_result.get("sections") or []
    chunks: List[str] = []
    for s in sections:
        stype = s.get("doc_type") or ""
        if doc_type_filter:
            if stype != doc_type_filter and not (
                stype == "scm" and doc_type_filter == "config_mgmt"
            ):
                continue
        chunks.append(str(s.get("title") or "").strip())
        chunks.append(str(s.get("text") or "").strip())
        for t in s.get("tables") or []:
            chunks.append(str(t.get("name") or "").strip())
            headers = t.get("headers") or []
            if isinstance(headers, list):
                chunks.append(" ".join(str(h) for h in headers))
            else:
                chunks.append(str(headers))
            # Include table row content so missing/regex rules can match cell values
            for row in t.get("rows") or []:
                if isinstance(row, list):
                    row_text = " ".join(str(c) for c in row if c)
                    if row_text.strip():
                        chunks.append(row_text)
                elif row:
                    chunks.append(str(row))
    return "\n".join(chunks)


def run_doc_rule_engine(
    doc_preprocess_result: Dict[str, Any],
    rules: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    문서용 L1 룰 엔진.
    - doc_preprocess_result 의 sections 로 풀텍스트를 만든 뒤
    - 각 룰의 pattern_type (missing / regex) 과 pattern 으로 검사해 위반 리스트 반환.
    """
    violations: List[Dict[str, Any]] = []
    if not rules:
        return violations

    # 전처리 결과에 실제로 존재하는 문서 타입만 대상으로 룰을 실행한다.
    # (예: 설계서만 업로드했는데 시험서 missing 룰이 위반으로 뜨는 문제 방지)
    sections = doc_preprocess_result.get("sections") or []
    available_types: set[str] = set()
    for s in sections:
        dt = (s.get("doc_type") or "").lower().strip()
        if not dt:
            continue
        # 전처리 결과의 scm 은 config_mgmt 로 간주
        if dt == "scm":
            dt = "config_mgmt"
        available_types.add(dt)

    # doc_type별 대표 파일 경로 캐시 (violation의 path 필드에 활용)
    # section의 "file" 필드는 "docs/design/foo.pdf#sec_1" 형태 → '#' 앞부분이 PDF 경로
    files_by_type: Dict[str, List[str]] = {}
    for s in sections:
        dt = (s.get("doc_type") or "").lower().strip()
        if dt == "scm":
            dt = "config_mgmt"
        if not dt:
            continue
        file_field = s.get("file") or ""
        base_file = file_field.split("#")[0] if "#" in file_field else file_field
        if base_file:
            files_by_type.setdefault(dt, [])
            if base_file not in files_by_type[dt]:
                files_by_type[dt].append(base_file)

    # doc_type별 풀텍스트 캐시 (design, config_mgmt, test)
    fulltext_by_type: Dict[str, str] = {}
    for dt in ("design", "config_mgmt", "test"):
        fulltext_by_type[dt] = _build_fulltext(doc_preprocess_result, dt)

    # 섹션별 위치 정보 캐시: doc_type → [(section_title, page_start, text_start_offset)]
    # DOC 위반에 어느 섹션에서 발생했는지 기록하기 위함
    def _build_section_index(dt: str) -> List[Dict[str, Any]]:
        """doc_type별 섹션 순서 + 누적 text offset 계산."""
        index: List[Dict[str, Any]] = []
        pos = 0
        for s in sections:
            stype = (s.get("doc_type") or "").lower().strip()
            if stype == "scm":
                stype = "config_mgmt"
            if stype != dt:
                continue
            title = str(s.get("title") or "").strip()
            text = str(s.get("text") or "").strip()
            index.append({
                "title": title,
                "page_start": s.get("page_start"),
                "start_offset": pos,
                "length": len(title) + 1 + len(text),
            })
            pos += len(title) + 1 + len(text) + 1  # +1 for newline separator
        return index

    section_index_by_type: Dict[str, List[Dict[str, Any]]] = {}
    for dt in ("design", "config_mgmt", "test"):
        if dt in available_types:
            section_index_by_type[dt] = _build_section_index(dt)

    def _find_section_for_offset(dt: str, offset: int) -> Optional[Dict[str, Any]]:
        """fulltext 내 offset에 해당하는 섹션 정보 반환."""
        idx = section_index_by_type.get(dt, [])
        best = None
        for sec in idx:
            if sec["start_offset"] <= offset:
                best = sec
            else:
                break
        return best

    for rule in rules:
        pattern_type = rule.get("pattern_type")
        pattern = rule.get("pattern")
        # semantic 타입도 pattern이 있으면 L1 키워드 트리거로 처리한다.
        # pattern 없는 semantic은 현재 L1으로 판단 불가 → 스킵 (L3 AI 연결 후 처리 예정)
        if pattern_type not in ("missing", "regex", "semantic") or not pattern:
            continue
        doc_type = rule.get("doc_type")
        if not doc_type:
            doc_type = "design"
        doc_type = str(doc_type).lower().strip()
        if doc_type == "scm":
            doc_type = "config_mgmt"
        if available_types and doc_type not in available_types:
            # 해당 타입 문서가 업로드/전처리되지 않았으면 룰 검사 자체를 생략
            continue
        fulltext = fulltext_by_type.get(doc_type, "")
        try:
            matcher = re.compile(pattern, re.IGNORECASE | re.DOTALL)
        except re.error:
            continue
        matched_iter = list(matcher.finditer(fulltext)) if fulltext else []
        matched = bool(matched_iter)

        # pattern_type: missing → 패턴이 하나도 안 나와야 "위반"으로 추가
        # doc_type에 해당하는 대표 파일 경로 (없으면 None)
        doc_files = files_by_type.get(doc_type, [])
        primary_path = doc_files[0] if doc_files else None

        if pattern_type == "missing" and not matched:
            violations.append(
                {
                    "rule_id": rule.get("id", ""),
                    "pattern_type": "missing",
                    "doc_type": doc_type,
                    "message": rule.get("name") or rule.get("id", "DOC"),
                    "severity": rule.get("severity", "medium"),
                    "path": primary_path,
                    "files": doc_files,
                    "ranges": [],
                    "needs_ai_review": False,
                }
            )
        # pattern_type: semantic → 패턴 매칭 여부와 관계없이 항상 AI 검토 대상으로 등록.
        # keyword_found=True: 키워드가 문서 어딘가에 있지만 맥락이 부적절할 수 있음 → AI 판단 필요
        # keyword_found=False: 키워드 자체가 없음 → 강한 위반 신호
        elif pattern_type == "semantic":
            violations.append(
                {
                    "rule_id": rule.get("id", ""),
                    "pattern_type": "semantic",
                    "doc_type": doc_type,
                    "message": rule.get("name") or rule.get("id", "DOC"),
                    "rule_description": rule.get("description", ""),
                    "severity": rule.get("severity", "medium"),
                    "path": primary_path,
                    "files": doc_files,
                    "ranges": [],
                    "needs_ai_review": True,
                    "keyword_found": matched,
                }
            )
        # pattern_type: regex → 패턴이 발견된 위치(ranges)를 함께 반환
        elif pattern_type == "regex" and matched:
            ranges = []
            for m in matched_iter:
                range_entry: Dict[str, Any] = {
                    "start_offset": m.start(),
                    "end_offset": m.end(),
                    "matched_text": m.group(),
                }
                # 매칭 위치에 해당하는 섹션 정보 첨부
                sec_info = _find_section_for_offset(doc_type, m.start())
                if sec_info:
                    range_entry["section_title"] = sec_info.get("title")
                    range_entry["page_start"] = sec_info.get("page_start")
                ranges.append(range_entry)
            v: Dict[str, Any] = {
                "rule_id": rule.get("id", ""),
                "doc_type": doc_type,
                "message": rule.get("name") or rule.get("id", "DOC"),
                "severity": rule.get("severity", "medium"),
                "path": primary_path,
                "files": doc_files,
                "ranges": ranges,
                "needs_ai_review": False,
            }
            # 첫 번째 매칭 섹션 정보를 최상위에도 노출
            if ranges and ranges[0].get("section_title"):
                v["section_title"] = ranges[0]["section_title"]
                v["page_start"] = ranges[0].get("page_start")
            violations.append(v)

    return violations
