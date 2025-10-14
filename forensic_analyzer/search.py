# forensic_analyzer/search.py
from __future__ import annotations
import csv
import fnmatch
import os
import re
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Tuple, Union

# API 호출 부분

def is_text_path(
    path: Union[str, Path],
    include_exts: Sequence[str] = ("txt", "log", "csv", "json", "xml", "md", "ini", "conf"),
) -> bool:
    """
    경량 텍스트 파일 후보를 확장자 기반으로 판정.
    - include_exts: 'txt'처럼 점(.) 없는 소문자 확장자 목록
    """
    p = Path(path)
    ext = p.suffix.lower().lstrip(".")
    return ext in {e.lower().lstrip(".") for e in include_exts}


def search_texts(
    root: Union[str, Path],
    keywords: Sequence[str],
    *,
    use_regex: bool = False,
    case_sensitive: bool = False,
    include_exts: Sequence[str] = ("txt", "log", "csv", "json", "xml", "md", "ini", "conf"),
    exclude_globs: Optional[Iterable[str]] = None,
    follow_symlinks: bool = False,
    max_file_size_bytes: int = 10 * 1024 * 1024,  # 10MB
    encodings: Sequence[str] = ("utf-8", "cp949", "latin-1"),
    preview_max_len: int = 240,
) -> List[Dict[str, Union[str, int]]]:
    """
    루트 폴더 아래 '경량 텍스트' 파일들을 라인 단위로 스캔하여 키워드(또는 정규식) 검색.
    반환: 행 딕셔너리 리스트
    - path: 파일 경로
    - line_no: 매칭된 라인 번호(1부터 시작)
    - match_span_start: 매칭 시작 인덱스
    - match_span_end: 매칭 끝 인덱스
    - line_preview: 매칭 라인의 미리보기(개행 제거, 길이 제한)
    - matched: 실제 매칭된 텍스트(정규식 사용 시 그룹 전체)
    - pattern: 검색 패턴(또는 키워드)
    """
    root = Path(root).resolve()
    _ex_patterns = tuple(exclude_globs or [])

    if not keywords:
        return []

    rows: List[Dict[str, Union[str, int]]] = []
    patterns = _compile_patterns(
        keywords,
        use_regex=use_regex,
        case_sensitive=case_sensitive,
    )

    for fpath in _iter_files(
        root,
        follow_symlinks=follow_symlinks,
        exclude_globs=_ex_patterns,
        include_exts=tuple(include_exts),
    ):
        # 크기 상한
        try:
            st = fpath.stat() if follow_symlinks else os.lstat(fpath)
            if st.st_size > max_file_size_bytes:
                continue
        except (OSError, PermissionError):
            continue

        # 인코딩 시도
        text_iter = _open_text_lines(fpath, encodings=encodings)
        if text_iter is None:
            continue

        try:
            for lineno, line in enumerate(text_iter, start=1):
                # 개행 제거(미리보기 안정화)
                display_line = line.rstrip("\r\n")
                for pat in patterns:
                    m = pat.search(line)
                    if not m:
                        continue
                    start, end = m.span()
                    snippet = _shrink(display_line, start, end, max_len=preview_max_len)
                    rows.append({
                        "path": str(fpath),
                        "line_no": lineno,
                        "match_span_start": start,
                        "match_span_end": end,
                        "line_preview": snippet,
                        "matched": m.group(0),
                        "pattern": pat.pattern,
                    })
        except (UnicodeDecodeError, OSError):
            # 읽는 중 인코딩 깨짐/IO 오류 → 파일 스킵
            continue

    return rows


def write_hits_csv(
    rows: List[Dict[str, Union[str, int]]],
    csv_path: Union[str, Path],
) -> None:
    """
    search_texts 결과(rows)를 CSV로 저장.
    - UTF-8 with BOM으로 저장하여 엑셀 호환성 확보
    """
    csv_path = Path(csv_path)
    csv_path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "path",
        "line_no",
        "match_span_start",
        "match_span_end",
        "matched",
        "pattern",
        "line_preview",
    ]

    with open(csv_path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


# 모듈 내부 함수 부분

def _iter_files(
    root: Path,
    *,
    follow_symlinks: bool,
    exclude_globs: Tuple[str, ...],
    include_exts: Tuple[str, ...],
) -> Iterator[Path]:
    """
    os.scandir 기반 재귀 순회.
    - exclude_globs와 매칭되면 디렉토리/파일 모두 스킵
    - include_exts 확장자만 텍스트 후보로 취급
    """
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as it:
                for entry in it:
                    p = Path(entry.path)
                    # 제외 규칙
                    if _is_excluded(p, exclude_globs):
                        continue

                    try:
                        if entry.is_dir(follow_symlinks=follow_symlinks):
                            stack.append(p)
                        elif entry.is_file(follow_symlinks=follow_symlinks):
                            if is_text_path(p, include_exts=include_exts):
                                yield p
                    except (OSError, PermissionError):
                        continue
        except (OSError, PermissionError):
            continue


def _is_excluded(path: Path, patterns: Tuple[str, ...]) -> bool:
    if not patterns:
        return False
    spath = str(path)
    name = path.name
    for pat in patterns:
        if fnmatch.fnmatch(spath, pat) or fnmatch.fnmatch(name, pat):
            return True
    return False


def _compile_patterns(
    keywords: Sequence[str],
    *,
    use_regex: bool,
    case_sensitive: bool,
) -> List[re.Pattern]:
    flags = 0 if case_sensitive else re.IGNORECASE
    patterns: List[re.Pattern] = []
    for kw in keywords:
        if use_regex:
            patterns.append(re.compile(kw, flags))
        else:
            # literal 검색 -> 정규식 escape로 부분 일치
            patterns.append(re.compile(re.escape(kw), flags))
    return patterns


def _open_text_lines(
    path: Path,
    *,
    encodings: Sequence[str],
) -> Optional[Iterator[str]]:
    """
    여러 인코딩 후보를 순차 시도하여 텍스트 라인 Iterator를 반환.
    실패 시 None.
    """
    for enc in encodings:
        try:
            f = path.open("r", encoding=enc, errors="strict")
            # 파일 객체를 제너레이터로 감싸 반환
            return _line_iter(f)
        except (UnicodeDecodeError, LookupError):
            # 인코딩 해석 실패 → 다음 인코딩 시도
            continue
        except (OSError, PermissionError):
            return None
    # 마지막 : 'errors=ignore'로 깨진 문자를 무시하고 읽기
    try:
        f = path.open("r", encoding=encodings[0] if encodings else "utf-8", errors="ignore")
        return _line_iter(f)
    except (OSError, PermissionError):
        return None


def _line_iter(f):
    """
    파일 핸들을 받아 한 줄씩 yield.
    호출 측에서 try/except로 감싸기 쉽게 분리.
    """
    try:
        for line in f:
            yield line
    finally:
        try:
            f.close()
        except Exception:
            pass


def _shrink(line: str, start: int, end: int, *, max_len: int = 240) -> str:
    """
    매칭 구간이 보이도록 앞/뒤를 적당히 축약한 미리보기 문자열 생성.
    - 너무 긴 라인은 가독성 위해 앞뒤를 잘라 '…'로 표시
    """
    if len(line) <= max_len:
        return line

    # match 중심으로 윈도우 구성
    match_center = (start + end) // 2
    half = max_len // 2
    left = max(0, match_center - half)
    right = min(len(line), left + max_len)

    snippet = line[left:right]
    prefix = "…" if left > 0 else ""
    suffix = "…" if right < len(line) else ""
    return f"{prefix}{snippet}{suffix}"
