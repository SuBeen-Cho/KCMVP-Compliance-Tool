"""
PreprocessDocsService: 문서 전처리

- 역할:
  - job 루트 하위 docs/ 디렉터리를 스캔해 문서 파일 목록을 수집하고,
  - 텍스트 기반 PDF에서 본문 텍스트 + 표 구조를 추출해
    DocumentSection / DocumentTable 형태에 가까운 JSON으로 변환한다.
- 표 영역 중복 제거: pdfplumber로 표 bbox를 구한 뒤, PyMuPDF 텍스트 추출 시
  해당 영역과 겹치는 블록은 제외해, 본문에 표 내용이 한 번만(표 형태로만) 나오게 한다.
"""

from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
import re


def _list_doc_files(job_root: Path) -> List[Path]:
  """job_root/docs/ 하위의 모든 파일 경로를 반환한다."""
  docs_root = (job_root / "docs").resolve()
  if not docs_root.is_dir():
      return []
  return [p for p in docs_root.rglob("*") if p.is_file()]


def _rects_overlap(a: Tuple[float, float, float, float], b: Tuple[float, float, float, float]) -> bool:
  """두 사각형 (x0, y0, x1, y1)이 겹치는지 여부."""
  ax0, ay0, ax1, ay1 = a
  bx0, by0, bx1, by1 = b
  return ax0 < bx1 and ax1 > bx0 and ay0 < by1 and ay1 > by0


def _rect_area(r: Tuple[float, float, float, float]) -> float:
  """사각형 (x0, y0, x1, y1) 넓이."""
  x0, y0, x1, y1 = r
  return max(0, (x1 - x0) * (y1 - y0))


def _extract_text_with_pymupdf(
    path: Path,
    exclude_bboxes_by_page: Optional[List[List[Tuple[float, float, float, float]]]] = None,
) -> Optional[str]:
    """
    PyMuPDF로 PDF 본문 텍스트를 추출한다.
    - exclude_bboxes_by_page: 페이지별 표 bbox 리스트가 주어지면, 해당 영역과 겹치는
      텍스트 블록은 제외해 표 내용이 본문에 중복되지 않게 한다.
    """
    page_texts = _extract_text_by_page_with_pymupdf(path, exclude_bboxes_by_page)
    if page_texts is None:
        return None
    text = "\n".join(t for t in page_texts if t).strip()
    return text or None


def _extract_text_by_page_with_pymupdf(
    path: Path,
    exclude_bboxes_by_page: Optional[List[List[Tuple[float, float, float, float]]]] = None,
) -> Optional[List[str]]:
    """
    PyMuPDF로 페이지별 본문 텍스트를 추출한다.
    - exclude_bboxes_by_page가 주어지면, 각 페이지에서 표 bbox와 겹치는 텍스트 블록은 제외한다.
    """
    try:
        import fitz  # type: ignore[import]
    except Exception:
        return None

    try:
        doc = fitz.open(str(path))
    except Exception:
        return None

    page_texts: List[str] = []
    try:
        for page_index, page in enumerate(doc):
            if exclude_bboxes_by_page and page_index < len(exclude_bboxes_by_page):
                bboxes = exclude_bboxes_by_page[page_index]
                try:
                    blocks = page.get_text("blocks") or []
                except Exception:
                    blocks = []
                block_texts: List[str] = []
                for block in blocks:
                    if not isinstance(block, (list, tuple)) or len(block) < 5:
                        continue
                    x0, y0, x1, y1 = block[0], block[1], block[2], block[3]
                    block_text = block[4] if isinstance(block[4], str) else ""
                    if not block_text or not block_text.strip():
                        continue
                    block_area = _rect_area((x0, y0, x1, y1))
                    # 블록 면적의 50% 이상이 표 bbox와 겹칠 때만 제외 (오탐 방지)
                    overlaps = False
                    for b in bboxes:
                        if _rects_overlap((x0, y0, x1, y1), b):
                            bx0, by0, bx1, by1 = b
                            ix0 = max(x0, bx0)
                            iy0 = max(y0, by0)
                            ix1 = min(x1, bx1)
                            iy1 = min(y1, by1)
                            inter = max(0, ix1 - ix0) * max(0, iy1 - iy0)
                            if block_area > 0 and inter / block_area >= 0.5:
                                overlaps = True
                                break
                    if overlaps:
                        continue
                    block_texts.append(block_text.strip())
                page_texts.append("\n".join(block_texts))
            else:
                try:
                    t = page.get_text("text") or ""
                except Exception:
                    t = ""
                page_texts.append(t.strip())
    finally:
        doc.close()

    return page_texts


def _extract_tables_and_bboxes_with_pdfplumber(
  path: Path,
) -> Tuple[List[Dict[str, Any]], List[List[Tuple[float, float, float, float]]]]:
  """
  pdfplumber로 표 구조와 페이지별 표 bbox를 추출한다.
  반환: (tables 리스트, bboxes_by_page).
  """
  tables: List[Dict[str, Any]] = []
  bboxes_by_page: List[List[Tuple[float, float, float, float]]] = []
  try:
      import pdfplumber  # type: ignore[import]
  except Exception:
      return tables, bboxes_by_page

  try:
      with pdfplumber.open(str(path)) as pdf:
          for page_index, page in enumerate(pdf.pages):
              page_bboxes: List[Tuple[float, float, float, float]] = []
              try:
                  page_area = _rect_area(page.bbox) if hasattr(page, "bbox") else 0
                  # 페이지 대부분을 덮는 큰 "표"는 제외(폼/레이아웃 오탐). 작은 표만 텍스트 제거 대상으로 쓴다.
                  area_ratio_threshold = 0.45
                  found = page.find_tables()
                  for t in found:
                      b = tuple(t.bbox)
                      if page_area > 0 and _rect_area(b) >= area_ratio_threshold * page_area:
                          continue
                      page_bboxes.append(b)
              except Exception:
                  pass
              bboxes_by_page.append(page_bboxes)

              try:
                  page_tables = page.extract_tables() or []
              except Exception:
                  continue
              for idx, tbl in enumerate(page_tables):
                  if not tbl or not isinstance(tbl, list):
                      continue
                  header = tbl[0] if len(tbl) > 0 else []
                  rows = tbl[1:] if len(tbl) > 1 else []
                  headers = [h.strip() if isinstance(h, str) else "" for h in header]
                  row_norm = [
                      [c.strip() if isinstance(c, str) else "" for c in (row or [])]
                      for row in rows
                  ]
                  tables.append(
                      {
                          "name": f"table_{page_index + 1}_{idx + 1}",
                          "page": page_index + 1,
                          "headers": headers,
                          "rows": row_norm,
                      }
                  )
  except Exception:
      pass

  return tables, bboxes_by_page


def _extract_tables_with_pdfplumber(path: Path) -> List[Dict[str, Any]]:
  """기존 호환용: 표만 추출."""
  tables, _ = _extract_tables_and_bboxes_with_pdfplumber(path)
  return tables


def _extract_markdown_with_markitdown(path: Path) -> Optional[str]:
    """
    MarkItDown(Microsoft)으로 PDF → Markdown 변환.
    - 텍스트 구조와 표를 GFM Markdown으로 변환 (Python 3.10+ 필요).
    - 실패 시 None 반환 (fallback으로 기존 PyMuPDF/pdfplumber 사용).
    """
    try:
        from markitdown import MarkItDown  # type: ignore[import]
        md = MarkItDown()
        result = md.convert(str(path))
        return (result.text_content or "").strip() or None
    except Exception:
        return None


def _tables_to_markdown(tables: List[Dict[str, Any]]) -> str:
    """
    pdfplumber JSON 표 목록을 GFM Markdown 표 형식으로 변환한다.
    프론트엔드에서 react-markdown + remark-gfm으로 렌더링 가능.
    """
    parts: List[str] = []
    for tbl in tables:
        headers = [str(h).strip() if h else "" for h in (tbl.get("headers") or [])]
        rows = tbl.get("rows") or []
        if not headers and not rows:
            continue
        # 헤더 없이 rows만 있는 경우 첫 행을 헤더로 사용
        if not headers and rows:
            headers = [str(c).strip() if c else "" for c in (rows[0] or [])]
            rows = rows[1:]
        if not headers:
            continue
        ncols = len(headers)
        # 헤더 행
        parts.append("| " + " | ".join(h.replace("\n", " ").replace("|", "\\|") for h in headers) + " |")
        # 구분자 행
        parts.append("| " + " | ".join("---" for _ in headers) + " |")
        # 데이터 행
        for row in rows:
            cells = [str(c).strip().replace("\n", " ").replace("|", "\\|") if c else "" for c in (row or [])]
            # 열 수 맞추기
            while len(cells) < ncols:
                cells.append("")
            cells = cells[:ncols]
            parts.append("| " + " | ".join(cells) + " |")
        parts.append("")
    return "\n".join(parts)


def _is_scanned_pdf(page_texts: List[str], threshold_chars_per_page: int = 30) -> bool:
    """
    페이지당 평균 텍스트 길이가 임계값 미만이면 스캔본(이미지 기반) PDF로 판정한다.

    - threshold_chars_per_page: 페이지당 최소 기대 문자 수 (기본 30자)
      · 완전한 스캔본만 OCR 대상으로 처리 (글자 약간 + 이미지 구성 페이지는 정상 처리)
      · 표지/빈 페이지 등 예외를 감안해 평균값 사용
    - 빈 page_texts(페이지 없음)는 False 반환
    """
    if not page_texts:
        return False
    total_chars = sum(len(t) for t in page_texts)
    avg_chars = total_chars / len(page_texts)
    return avg_chars < threshold_chars_per_page


def _ocr_pages_with_gemini(
    path: Path,
    page_indices: List[int],
    api_key: str,
    max_pages: int = 30,
) -> Dict[int, str]:
    """
    스캔본 PDF 페이지를 Gemini Vision으로 OCR하여 {page_index: ocr_text} 반환.

    - 텍스트 레이어 없는 페이지만 대상으로 호출할 것 (비용 절감).
    - max_pages: 처리 페이지 수 상한 (API 비용 제어)
    - 실패 페이지는 결과 dict에서 제외.
    """
    if not api_key or not page_indices:
        return {}
    results: Dict[int, str] = {}
    try:
        import fitz  # type: ignore[import]
        from google import genai  # type: ignore[import]
        from google.genai import types as genai_types  # type: ignore[import]
    except Exception:
        return {}

    _OCR_PROMPT = (
        "이 이미지는 KCMVP 암호모듈 관련 문서(설계서/시험서/형상관리문서)의 스캔 페이지입니다. "
        "페이지에 있는 모든 텍스트를 정확하게 추출하여 그대로 출력하세요. "
        "표가 있으면 마크다운 표(| 헤더 | ... |) 형식으로 변환하세요. "
        "이미지 설명이나 부가 설명은 포함하지 마세요. 추출된 텍스트만 출력하세요."
    )

    try:
        client = genai.Client(api_key=api_key)
        doc = fitz.open(str(path))
        processed = 0
        try:
            for pg_idx in page_indices:
                if processed >= max_pages:
                    break
                if pg_idx < 0 or pg_idx >= len(doc):
                    continue
                page = doc[pg_idx]
                try:
                    # 페이지 전체를 이미지로 렌더링 (해상도 150 DPI)
                    mat = fitz.Matrix(150 / 72, 150 / 72)
                    pix = page.get_pixmap(matrix=mat)
                    img_bytes = pix.tobytes("png")
                    pix = None
                    response = client.models.generate_content(
                        model="gemini-2.0-flash",
                        contents=[
                            genai_types.Part.from_bytes(
                                data=img_bytes,
                                mime_type="image/png",
                            ),
                            _OCR_PROMPT,
                        ],
                    )
                    ocr_text = (response.text or "").strip()
                    if ocr_text:
                        results[pg_idx] = ocr_text
                    processed += 1
                except Exception:
                    continue
        finally:
            doc.close()
    except Exception:
        pass
    return results


def _describe_page_images_with_gemini(
    path: Path,
    page_indices: List[int],
    api_key: str,
    max_images: int = 8,
) -> List[Dict[str, Any]]:
    """
    지정된 페이지들에서 이미지를 추출해 Gemini Vision으로 한국어 설명을 생성한다.
    반환: [{"page": 1, "index": 0, "description": "..."}]
    - 50×50 픽셀 미만 소형 이미지(아이콘, 로고 등)는 건너뛴다.
    - max_images: PDF 전체 처리 이미지 수 상한
    """
    if not api_key or not page_indices:
        return []
    results: List[Dict[str, Any]] = []
    try:
        import fitz  # type: ignore[import]
        from google import genai  # type: ignore[import]
        from google.genai import types as genai_types  # type: ignore[import]
    except Exception:
        return []

    try:
        client = genai.Client(api_key=api_key)
        doc = fitz.open(str(path))
        img_count = 0
        try:
            for pg_idx in page_indices:
                if img_count >= max_images:
                    break
                if pg_idx < 0 or pg_idx >= len(doc):
                    continue
                page = doc[pg_idx]
                try:
                    img_list = page.get_images(full=True)
                except Exception:
                    continue
                for img_order, img_info in enumerate(img_list):
                    if img_count >= max_images:
                        break
                    try:
                        xref = img_info[0]
                        pix = fitz.Pixmap(doc, xref)
                        # 소형 이미지(아이콘/로고) 제외
                        if pix.width < 50 or pix.height < 50:
                            pix = None
                            continue
                        # CMYK → RGB 변환
                        if pix.n - (1 if pix.alpha else 0) > 3:
                            pix = fitz.Pixmap(fitz.csRGB, pix)
                        img_bytes = pix.tobytes("png")
                        pix = None
                        response = client.models.generate_content(
                            model="gemini-2.0-flash",
                            contents=[
                                genai_types.Part.from_bytes(
                                    data=img_bytes,
                                    mime_type="image/png",
                                ),
                                (
                                    "이 이미지는 KCMVP 암호모듈 설계 문서에 포함된 그림입니다. "
                                    "한국어로 간결하게 설명해주세요. "
                                    "다이어그램·흐름도·구성도·표 등의 내용을 포함해 설명하세요. "
                                    "3~5문장으로 요약해주세요."
                                ),
                            ],
                        )
                        desc = (response.text or "").strip()
                        if desc:
                            results.append(
                                {
                                    "page": pg_idx + 1,
                                    "index": img_order,
                                    "description": desc,
                                }
                            )
                            img_count += 1
                    except Exception:
                        continue
        finally:
            doc.close()
    except Exception:
        pass
    return results


def _build_section_markdown(
    text: Optional[str],
    tables: List[Dict[str, Any]],
    image_descriptions: List[Dict[str, Any]],
) -> Optional[str]:
    """
    섹션의 text, tables, image_descriptions를 조합해 Markdown 문자열을 생성한다.
    - text: 섹션 본문 (plain text)
    - tables: pdfplumber 추출 JSON 표 목록
    - image_descriptions: Gemini Vision 이미지 설명 목록
    반환: Markdown 문자열 (react-markdown + remark-gfm으로 렌더링 가능)
    """
    parts: List[str] = []
    if text and text.strip():
        parts.append(text.strip())
    tables_md = _tables_to_markdown(tables)
    if tables_md.strip():
        if parts:
            parts.append("")
        parts.append(tables_md.strip())
    for img in image_descriptions:
        page = img.get("page", "?")
        desc = (img.get("description") or "").strip()
        if desc:
            parts.append(f"\n> 🖼️ **이미지 (페이지 {page})**: {desc}")
    if not parts:
        return None
    return "\n\n".join(parts)


def run_doc_preprocess(job_root: Path) -> Dict[str, Any]:
  """
  문서 전처리.

  - docs/ 하위 각 파일을 하나의 DocumentSection 으로 간주하고,
    텍스트 기반 PDF의 경우 본문 텍스트(text)는 표 영역을 제외해 추출하고,
    표 목록(tables)은 pdfplumber로 추출해 중복 없이 채운다.
  """
  sections: List[Dict[str, Any]] = []
  errors: List[Dict[str, Any]] = []

  job_root_resolved = job_root.resolve()
  docs_root = (job_root / "docs").resolve()

  # TOC 기반 섹션 분리에 사용할 최소 항목 수
  MIN_TOC_ENTRIES = 3

  def _int_or_roman_to_int(s: str) -> Optional[int]:
      s = (s or "").strip()
      if not s:
          return None
      if s.isdigit():
          try:
              return int(s)
          except ValueError:
              return None
      roman_map = {
          "I": 1,
          "II": 2,
          "III": 3,
          "IV": 4,
          "V": 5,
          "VI": 6,
          "VII": 7,
          "VIII": 8,
          "IX": 9,
          "X": 10,
      }
      return roman_map.get(s.upper())

  def _parse_toc_from_pages(page_texts: List[str]) -> Tuple[List[Dict[str, Any]], int]:
      """
      page_texts의 전체 페이지에서 '목차' 블록을 찾아 (id, title, page) 리스트를 추출한다.
      반환: (toc_entries, toc_last_physical_page) - 마지막 TOC 항목이 발견된 물리 페이지.
      """
      if not page_texts:
          return [], 0

      lines_with_page: List[Tuple[int, str]] = []

      # 현재는 목차가 뒤쪽 페이지에 위치하는 설계서도 있어, 전체 페이지를 대상으로 검사한다.
      for page_no, page_text in enumerate(page_texts, start=1):
          for line in (page_text or "").splitlines():
              lines_with_page.append((page_no, line))

      start_idx: Optional[int] = None
      toc_header_re = re.compile(r"(목\s*차|Contents)", re.IGNORECASE)
      for idx, (_, line) in enumerate(lines_with_page):
          if toc_header_re.search(line or ""):
              start_idx = idx
              break

      if start_idx is None:
          start_idx = 0

      # 페이지 헤더 ("4 / 20", "5 / 20" 등)는 TOC 항목으로 오인하지 않도록 스킵
      page_marker_toc_re = re.compile(r"^\s*\d+\s*/\s*\d+\s*$")
      # 패턴 A: 한 줄에 번호 + 선택적 점 + 제목 + 페이지 ("1 개요 ... 4", "1. 개요 ... 4" 모두 처리)
      dec_singleline_re = re.compile(
          r"^\s*(\d+(?:\.\d+)*)\.?\s+(.+?)\s*(?:[\.·•…]+\s*)?([IVXLC\d]+)\s*$"
      )
      # 패턴 B-1: 번호만 있는 줄
      dec_number_only_re = re.compile(r"^\s*(\d+(?:\.\d+)*)\s*$")
      # 패턴 B-2: 제목 + 페이지 줄
      title_page_re = re.compile(r"^\s*(.+?)\s*(?:[\.·•…]+\s*)?([IVXLC\d]+)\s*$")
      # 패턴 C: "제 N 장/절/항 제목 ..... 페이지"
      chapter_singleline_re = re.compile(
          r"^\s*(제\s*\d+\s*[장절항편])\s+(.+?)\s*(?:[\.·•…]+\s*)?([IVXLC\d]+)\s*$"
      )

      toc_entries: List[Dict[str, Any]] = []
      # TOC 페이지(목차가 실제로 존재하는 물리 페이지)를 별도로 기록
      toc_physical_page: int = lines_with_page[start_idx][0] if start_idx < len(lines_with_page) else 1
      toc_last_physical_page: int = toc_physical_page
      i = start_idx

      while i < len(lines_with_page):
          phys_page, line = lines_with_page[i]
          line = line or ""

          # TOC 페이지가 끝나고 본문 페이지로 넘어가면 파싱 중단
          # (목차 직후 페이지부터는 본문이므로 TOC 파싱 범위를 목차 페이지로 제한)
          if phys_page > toc_physical_page + 2:
              break

          # "4 / 20" 형태의 페이지 헤더는 TOC 항목이 아님
          if page_marker_toc_re.match(line):
              i += 1
              continue

          # 장/절/항 패턴 먼저 시도
          mC = chapter_singleline_re.match(line)
          if mC:
              page_val = _int_or_roman_to_int(mC.group(3))
              if page_val is not None:
                  toc_entries.append(
                      {
                          "id": mC.group(1).replace(" ", ""),
                          "title": mC.group(2).strip(),
                          "page": page_val,
                      }
                  )
                  toc_last_physical_page = phys_page
              i += 1
              continue

          mA = dec_singleline_re.match(line)
          if mA:
              # 제목이 "/" 하나뿐인 경우는 페이지 헤더 오탐 → 스킵
              title_candidate = mA.group(2).strip()
              if title_candidate and title_candidate != "/":
                  page_val = _int_or_roman_to_int(mA.group(3))
                  if page_val is not None:
                      toc_entries.append(
                          {
                              "id": mA.group(1),
                              "title": title_candidate,
                              "page": page_val,
                          }
                      )
                      toc_last_physical_page = phys_page
              i += 1
              continue

          m_num = dec_number_only_re.match(line)
          if m_num and i + 1 < len(lines_with_page):
              _, line2 = lines_with_page[i + 1]
              line2 = line2 or ""
              m_title = title_page_re.match(line2)
              if m_title:
                  page_val = _int_or_roman_to_int(m_title.group(2))
                  if page_val is not None:
                      toc_entries.append(
                          {
                              "id": m_num.group(1),
                              "title": m_title.group(1).strip(),
                              "page": page_val,
                          }
                      )
                      toc_last_physical_page = phys_page
                  i += 2
                  continue

          i += 1

      if len(toc_entries) < MIN_TOC_ENTRIES:
          return [], 0

      return toc_entries, toc_last_physical_page

  def _detect_page_offset(
      page_texts: List[str],
      toc_entries: List[Dict[str, Any]],
      after_physical_page: int,
      search_range: int = 8,
  ) -> int:
      """
      TOC 페이지 번호와 실제 물리 페이지 사이의 오프셋을 자동 감지한다.
      - page_texts: 물리 페이지 텍스트 목록 (0-indexed)
      - toc_entries: _parse_toc_from_pages 결과
      - after_physical_page: TOC가 끝나는 물리 페이지 번호
      반환: offset (물리 페이지 = doc 페이지 + offset)
      """
      if not toc_entries or not page_texts:
          return 0

      first_entry = toc_entries[0]
      doc_page = first_entry.get("page") or 1
      title_words = [
          w for w in (first_entry.get("title") or "").split()
          if len(w) >= 2
      ][:3]
      if not title_words:
          return 0

      title_pattern = re.compile(
          "|".join(re.escape(w) for w in title_words),
          re.IGNORECASE,
      )

      # TOC 종료 이후 페이지들을 탐색
      search_start = max(after_physical_page, doc_page)
      for phys_page in range(search_start, min(search_start + search_range, len(page_texts) + 1)):
          if phys_page > len(page_texts):
              break
          page_text = page_texts[phys_page - 1] or ""
          if title_pattern.search(page_text):
              offset = phys_page - doc_page
              return offset

      return 0

  def _build_sections_from_toc(
      path_display: str,
      doc_type: str,
      page_texts: List[str],
      tables: List[Dict[str, Any]],
      toc_entries: List[Dict[str, Any]],
      page_offset: int = 0,
  ) -> List[Dict[str, Any]]:
      """
      TOC 항목과 페이지별 텍스트/표 정보를 바탕으로 섹션 리스트를 구성한다.
      page_offset: 물리 페이지 = doc 페이지 + offset (커버/TOC 페이지 수 보정)
      """
      sections_from_toc: List[Dict[str, Any]] = []
      total_pages = len(page_texts)

      # 페이지 번호만 있는 줄(예: "3", "12") 또는 "3 / 20" 형태는 본문에서 제거한다.
      page_marker_re = re.compile(r"^\s*\d+\s*/\s*\d+\s*$")
      single_page_number_re = re.compile(r"^\s*\d+\s*$")

      for idx, entry in enumerate(toc_entries):
          start_page = entry.get("page") or 1
          if idx + 1 < len(toc_entries):
              next_entry = toc_entries[idx + 1]
              next_page = next_entry.get("page") or start_page
              end_page = max(start_page, next_page - 1)
          else:
              end_page = total_pages or start_page

          # 물리 페이지 번호 = doc 페이지 번호 + page_offset
          phys_start = start_page + page_offset
          phys_end = end_page + page_offset

          # TOC가 실제 페이지 수를 초과하는 경우: 마지막 유효 페이지로 클램프
          # (TOC 페이지 번호와 실제 PDF 분량이 다를 때 빈 섹션 방지)
          if phys_start > total_pages and total_pages > 0:
              phys_start = total_pages
          phys_end = max(phys_start, min(phys_end, total_pages if total_pages else phys_end))

          text_parts: List[str] = []
          for p in range(phys_start, phys_end + 1):
              if 1 <= p <= total_pages:
                  raw = page_texts[p - 1] or ""
                  # 페이지 단위 텍스트를 줄 단위로 나눈 뒤, 페이지 번호 줄은 제거
                  filtered_lines: List[str] = []
                  for line in raw.splitlines():
                      if page_marker_re.match(line or "") or single_page_number_re.match(
                          line or ""
                      ):
                          continue
                      filtered_lines.append(line)
                  t = "\n".join(filtered_lines).strip()
                  if t:
                      text_parts.append(t)
          section_text = "\n".join(text_parts).strip() or None

          section_tables = [
              tbl
              for tbl in tables
              if isinstance(tbl.get("page"), int)
              and phys_start <= int(tbl["page"]) <= phys_end
          ]

          section_id = entry.get("id") or f"{idx+1}"
          raw_title = (entry.get("title") or "").strip()
          if raw_title:
              title = f"{section_id}. {raw_title}"
          else:
              title = section_id

          level = section_id.count(".") + 1

          sections_from_toc.append(
              {
                  "doc_type": doc_type,
                  "file": f"{path_display}#sec_{section_id}",
                  "title": title,
                  "level": level,
                  "page_start": start_page,
                  "page_end": end_page,
                  "section_type": None,
                  "text": section_text,
                  "tables": section_tables,
              }
          )

      return sections_from_toc

  def _split_text_into_sections(text: str) -> List[Dict[str, Any]]:
      """
      헤더 패턴(예: '2.1 제목', 'Ⅱ. 일반사항', 'Ⅲ-1. 암호모듈 명세')을 기준으로 섹션을 나눈다.
      - section_id: "2.1", "Ⅱ", "Ⅲ-1" 등 번호/식별자
      - title: "2.1 제목" / "Ⅱ. 일반사항" 등
      - level:
          * '2'         → 1
          * '2.1'       → 2
          * '2.1.3'     → 3
          * 'Ⅱ'        → 1
          * 'Ⅲ-1'      → 2
      """
      lines = text.splitlines()

      # 숫자 기반 헤더: "2 제목", "2.1 제목", "2.1.3 제목"
      dec_heading_re = re.compile(r"^\s*(\d+(?:\.\d+)*)\s+(.+)$")
      # 유니코드 로마자 장: "Ⅰ. 개요", "Ⅱ. 일반사항"
      roman_heading_re = re.compile(r"^\s*([ⅠⅡⅢⅣⅤⅥⅦⅧⅨⅩ]+)\.\s+(.+)$")
      # 로마자-숫자 절: "Ⅲ-1. 암호모듈 명세"
      roman_sub_heading_re = re.compile(r"^\s*([ⅠⅡⅢⅣⅤⅥⅦⅧⅨⅩ]+-\d+)\.\s+(.+)$")
      # 제 N 장/절/항/편: "제1장 개요", "제 2 절 일반사항"
      chapter_re = re.compile(r"^\s*(제\s*\d+\s*[장절항편])\s+(.+)$")
      # 한글 가나다 항목: "가. 목적", "나. 범위" (3글자 이상 본문에는 미적용)
      korean_alpha_re = re.compile(r"^\s*([가나다라마바사아자차카타파하])\.\s+(.+)$")
      # 괄호 번호: "(1) 암호 알고리즘", "(가) 목적"
      paren_num_re = re.compile(r"^\s*\(([가-힣\d]+)\)\s+(.+)$")
      # 특수문자 불릿 헤더: "■ 암호모듈 식별", "▶ 동작환경"
      bullet_heading_re = re.compile(r"^\s*[■▶●◆▷◎☞→]\s+(.+)$")
      # 페이지 번호 패턴: "1 / 20", "2 / 20" 등은 섹션 헤더로 취급하지 않고 건너뛴다.
      page_marker_re = re.compile(r"^\s*\d+\s*/\s*\d+\s*$")
      # 페이지 번호가 줄 전체에 단독으로 찍힌 경우(예: "3")도 본문에서 제거한다.
      single_page_number_re = re.compile(r"^\s*\d+\s*$")

      result: List[Dict[str, Any]] = []
      current_id: Optional[str] = None
      current_title: Optional[str] = None
      current_level: int = 1
      buf: List[str] = []

      def flush():
          if current_id is None and not buf:
              return
          body = "\n".join(buf).strip()
          result.append(
              {
                  "section_id": current_id,
                  "title": current_title or (current_id or "본문"),
                  "level": current_level,
                  "text": body or None,
              }
          )

      for line in lines:
          # 페이지 마커(1 / 20 등)나 페이지 번호만 있는 줄은 섹션/본문에서 모두 제외
          if page_marker_re.match(line or "") or single_page_number_re.match(line or ""):
              continue

          m = None
          detected_level = 1

          # 우선순위 순으로 헤더 패턴 시도
          if not m:
              m = roman_sub_heading_re.match(line)
              if m:
                  detected_level = 2
          if not m:
              m = roman_heading_re.match(line)
              if m:
                  detected_level = 1
          if not m:
              m = chapter_re.match(line)
              if m:
                  # 장→1, 절→2, 항/편→3
                  sid_raw = m.group(1).replace(" ", "")
                  if "장" in sid_raw or "편" in sid_raw:
                      detected_level = 1
                  elif "절" in sid_raw:
                      detected_level = 2
                  else:
                      detected_level = 3
          if not m:
              m = dec_heading_re.match(line)
              if m:
                  detected_level = m.group(1).count(".") + 1
          if not m:
              m = korean_alpha_re.match(line)
              if m:
                  detected_level = 2
          if not m:
              mb = bullet_heading_re.match(line)
              if mb:
                  flush()
                  buf = []
                  current_id = None
                  current_title = mb.group(1).strip()
                  current_level = 2
                  continue
          if not m:
              mp = paren_num_re.match(line)
              if mp:
                  flush()
                  buf = []
                  current_id = f"({mp.group(1)})"
                  current_title = f"({mp.group(1)}) {mp.group(2).strip()}"
                  current_level = 3
                  continue

          if m:
              # 이전 섹션 마감
              flush()
              buf = []
              sid = m.group(1)
              title_body = m.group(2).strip()
              current_id = sid
              # 원문 형태의 제목을 최대한 유지
              current_title = f"{sid} {title_body}"
              current_level = detected_level
              continue

          buf.append(line)

      flush()
      return result

  for fp in _list_doc_files(job_root):
      try:
          try:
              rel = fp.resolve().relative_to(job_root_resolved)
              path_display = str(rel).replace("\\", "/")
          except Exception:
              path_display = str(fp)

          try:
              rel_from_docs = fp.resolve().relative_to(docs_root)
              parts = rel_from_docs.parts
              doc_type = parts[0] if parts else "unknown"
          except Exception:
              doc_type = "unknown"

          text_content: Optional[str] = None
          page_start: Optional[int] = None
          page_end: Optional[int] = None
          tables: List[Dict[str, Any]] = []
          page_texts: Optional[List[str]] = None
          # 페이지번호 → 이미지 설명 매핑 (Gemini Vision으로 채워짐)
          _image_by_page: Dict[int, Dict[str, Any]] = {}
          # MarkItDown 전체 변환 결과 (PDF 한정, 없으면 None)
          _markitdown_full: Optional[str] = None

          if fp.suffix.lower() == ".pdf":
              tables, bboxes_by_page = _extract_tables_and_bboxes_with_pdfplumber(fp)
              page_texts = _extract_text_by_page_with_pymupdf(
                  fp, exclude_bboxes_by_page=bboxes_by_page
              )
              if page_texts is not None:
                  text_content = "\n".join(t for t in page_texts if t).strip() or None

              # ── MarkItDown: PDF 전체를 Markdown으로 변환 (표 구조 개선) ──────
              _markitdown_full: Optional[str] = _extract_markdown_with_markitdown(fp)

              # ── Gemini API 키 로드 ────────────────────────────────────────────
              try:
                  from app.config import settings as _cfg  # noqa: PLC0415
                  _api_key = _cfg.GOOGLE_API_KEY
              except Exception:
                  _api_key = ""

              # ── 스캔본 감지 → Gemini OCR로 텍스트 보완 ───────────────────────
              _is_scanned = page_texts is not None and _is_scanned_pdf(page_texts)
              if _is_scanned and _api_key and page_texts is not None:
                  # 텍스트가 빈 페이지만 OCR 대상으로 선별 (비용 최적화)
                  _scan_page_indices = [
                      i for i, t in enumerate(page_texts) if len(t.strip()) < 30
                  ]
                  if _scan_page_indices:
                      _ocr_results = _ocr_pages_with_gemini(
                          fp, _scan_page_indices, _api_key, max_pages=30
                      )
                      # OCR 결과로 빈 페이지 텍스트 교체
                      for _pg_idx, _ocr_text in _ocr_results.items():
                          page_texts[_pg_idx] = _ocr_text
                      # 전체 text_content 재구성
                      text_content = "\n".join(t for t in page_texts if t).strip() or None

              # ── Gemini Vision 이미지 설명 추출 (스캔본이 아닌 경우만) ──────────
              if page_texts and _api_key and not _is_scanned:
                  _all_imgs = _describe_page_images_with_gemini(
                      fp, list(range(len(page_texts))), _api_key, max_images=8
                  )
                  for _d in _all_imgs:
                      _pg = _d.get("page")
                      if _pg and _pg not in _image_by_page:
                          _image_by_page[_pg] = _d

              # TOC 기반 섹션 분리 시도
              if page_texts:
                  toc_entries, toc_last_phys_page = _parse_toc_from_pages(page_texts)
                  if toc_entries:
                      page_offset = _detect_page_offset(
                          page_texts, toc_entries, toc_last_phys_page
                      )
                      toc_sections = _build_sections_from_toc(
                          path_display=path_display,
                          doc_type=doc_type,
                          page_texts=page_texts,
                          tables=tables,
                          toc_entries=toc_entries,
                          page_offset=page_offset,
                      )
                      if toc_sections:
                          # markdown_content: text + Markdown 표 + 이미지 설명
                          for _sec in toc_sections:
                              _pg_s = _sec.get("page_start") or 1
                              _pg_e = _sec.get("page_end") or _pg_s
                              _sec_imgs = [
                                  _image_by_page[p]
                                  for p in range(_pg_s, _pg_e + 1)
                                  if p in _image_by_page
                              ]
                              _sec["markdown_content"] = _build_section_markdown(
                                  _sec.get("text"), _sec.get("tables", []), _sec_imgs
                              )
                          sections.extend(toc_sections)
                          continue

          # TOC 기반 분리에 실패한 경우: 기존 헤더 기반 섹션 분리 사용
          if text_content:
              split_sections = _split_text_into_sections(text_content)
          else:
              split_sections = []

          if split_sections:
              # 페이지 경계를 이용해 섹션별 표 할당
              # page_texts가 있으면 각 섹션 텍스트가 시작하는 페이지를 추정한다.
              page_boundaries: List[Tuple[int, int, int]] = []  # (start_offset, end_offset, page_num)
              if page_texts and text_content:
                  cum = 0
                  for pidx, pt in enumerate(page_texts):
                      page_boundaries.append((cum, cum + len(pt), pidx + 1))
                      cum += len(pt) + 1

              def _offset_to_page(offset: int) -> int:
                  for s, e, pnum in page_boundaries:
                      if s <= offset < e:
                          return pnum
                  return len(page_texts) if page_texts else 1

              # 각 섹션의 텍스트 시작 위치→페이지 추정
              sec_page_starts: List[int] = []
              search_from = 0
              for sec in split_sections:
                  sec_text = sec.get("text") or ""
                  probe = sec_text[:80].strip()
                  if probe and page_boundaries:
                      pos = text_content.find(probe, search_from)
                      if pos >= 0:
                          search_from = pos
                          sec_page_starts.append(_offset_to_page(pos))
                          continue
                  sec_page_starts.append(sec_page_starts[-1] if sec_page_starts else 1)

              # 섹션별로 "가상 파일"처럼 보이도록 file 이름에 #section_id를 붙인다.
              for idx, sec in enumerate(split_sections):
                  section_id = sec.get("section_id") or f"section{idx+1}"
                  sec_pg_start = sec_page_starts[idx]
                  sec_pg_end = (sec_page_starts[idx + 1] if idx + 1 < len(sec_page_starts)
                                else (len(page_texts) if page_texts else sec_pg_start))
                  # 해당 페이지 범위에 속하는 표만 할당 (페이지 정보 없으면 모두 첫 섹션에)
                  if page_boundaries and tables:
                      sec_tables = [
                          t for t in tables
                          if isinstance(t.get("page"), int)
                          and sec_pg_start <= int(t["page"]) <= sec_pg_end
                      ]
                  else:
                      sec_tables = tables if idx == 0 else []
                  _split_imgs = [
                      _image_by_page[p]
                      for p in range(sec_pg_start, sec_pg_end + 1)
                      if p in _image_by_page
                  ]
                  sections.append(
                      {
                          "doc_type": doc_type,
                          "file": f"{path_display}#{section_id}",
                          "title": sec.get("title") or fp.stem,
                          "level": sec.get("level") or 1,
                          "page_start": sec_pg_start,
                          "page_end": sec_pg_end,
                          "section_type": None,
                          "text": sec.get("text"),
                          "tables": sec_tables,
                          "markdown_content": _build_section_markdown(
                              sec.get("text"), sec_tables, _split_imgs
                          ),
                      }
                  )
          else:
              # 섹션 헤더를 찾지 못하면 파일 전체를 하나의 섹션으로 취급
              # MarkItDown 전체 결과가 있으면 이미지 설명과 결합해 사용
              _fallback_md: Optional[str] = None
              if _markitdown_full:
                  _img_blocks = "".join(
                      f"\n\n> 🖼️ **이미지 (페이지 {d.get('page', '?')})**: {d.get('description', '').strip()}"
                      for d in _image_by_page.values()
                      if d.get("description")
                  )
                  _fallback_md = _markitdown_full + _img_blocks if _img_blocks else _markitdown_full
              else:
                  _fallback_md = _build_section_markdown(
                      text_content, tables, list(_image_by_page.values())
                  )
              sections.append(
                  {
                      "doc_type": doc_type,
                      "file": path_display,
                      "title": fp.stem,
                      "level": 1,
                      "page_start": page_start,
                      "page_end": page_end,
                      "section_type": None,
                      "text": text_content,
                      "tables": tables,
                      "markdown_content": _fallback_md,
                      "is_scanned": _is_scanned if fp.suffix.lower() == ".pdf" else False,
                  }
              )
      except Exception as e:  # pragma: no cover - 방어 코드
          errors.append({"file": str(fp), "error": str(e)})

  return {"sections": sections, "errors": errors}

