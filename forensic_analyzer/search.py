# forensic_analyzer/search.py
"""텍스트 파일 키워드·정규식 검색.

대상 파일은 ``inventory.iter_files``로 고르므로, 인벤토리와 같은 제외 규칙과 심볼릭
링크 정책을 따른다. 검색하지 못한 파일은 이유와 함께 따로 기록한다. 포렌식에서는
"검색했는데 없음"과 "검색하지 못함"을 구분해야 하기 때문이다.

인코딩 처리 순서:
    1. 파일 앞부분(64KB)으로 인코딩을 고른다. 시그니처 판별과 **같은 함수**
       (``textutil.detect_text_encoding``)와 같은 기본 목록(UTF-8 → CP949 → Shift-JIS →
       GBK → CP1252, BOM, BOM 없는 UTF-16)을 쓰므로, 시그니처에서 텍스트로 인정한
       파일은 검색에서도 같은 인코딩으로 읽힌다.
    2. 고른 인코딩이 UTF-8(또는 UTF-16·UTF-32)이면 파일 전체를 엄격 모드로 디코딩한다.
       성공하면 끝이다.
    3. 실패했거나, 고른 인코딩이 CP949 같은 레거시 인코딩이면 **줄 단위로** 읽는다.
       줄마다 UTF-8 → (파일의 대표 레거시 인코딩) → 나머지 목록 순서로 시도한다.
       대표 레거시 인코딩은 **UTF-8로 읽히지 않는 줄만 모아서** 판정한다. 파일 전체로 판정하면
       UTF-8 줄이 섞여 CP949 판정이 실패하고, CP949 한글도 받아들이는 GBK가 대신 뽑혀
       CP949 줄을 중국어로 잘못 읽기 때문이다. CP1252처럼 거의 모든 바이트를 받아들이는
       인코딩은 앞으로 당기지 않고 항상 마지막에 시도한다.
       레거시 인코딩을 파일 전체에 바로 적용하지 않는 이유는, CP949가 UTF-8 한글 바이트도
       엉뚱한 글자로 "성공적으로" 읽어 버려서, UTF-8 줄이 섞인 파일에서 그 줄들을 놓치기
       때문이다. 처음 성공한 인코딩을 그 줄의 인코딩으로 기록하고, 어떤 인코딩으로도
       안 되는 줄만 대체 문자(U+FFFD)로 읽어 ``utf-8+replace``처럼 기록한다.
       이렇게 하면 다음 경우를 모두 놓치지 않는다.

       - 앞부분은 영문이고 뒤에 CP949 한글이 나오는 윈도우 로그(앞부분만 보면 UTF-8로 판정됨)
       - 여러 프로그램이 같은 로그에 써서 UTF-8 줄과 CP949 줄이 섞인 파일(앞부분만 보면
         CP949로 판정되고, CP949로 전체를 읽으면 UTF-8 줄이 깨진다)
       - 텍스트 뒤에 바이너리를 붙인 위장 파일, 끝이 잘린 파일

       UTF-8을 줄마다 가장 먼저 시도하는 이유는, UTF-8 엄격 디코딩은 규칙이 까다로워 다른
       인코딩의 한글이 우연히 통과하는 일이 거의 없기 때문이다(반대로 CP949는 UTF-8 한글
       바이트도 엉뚱한 글자로 받아들이는 경우가 많다).
    4. UTF-16·UTF-32는 줄바꿈 바이트가 달라 줄 단위로 나눌 수 없으므로, 2번이 실패하면
       깨진 부분만 대체 문자로 읽는다. 어떤 경우에도 디코딩 오류로 검색이 멈추지 않는다.

줄 번호:
    줄은 편집기와 같게 ``\\n``, ``\\r\\n``, ``\\r``에서만 나눈다. 파이썬의 ``str.splitlines()``는
    폼피드(``\\x0c``)나 ``\\u2028`` 등에서도 줄을 나눠, 인쇄용 로그처럼 폼피드가 들어간 파일에서
    줄 번호가 실제보다 밀리기 때문이다.

    같은 바이트열이 여러 인코딩으로 동시에 디코딩될 수 있다. 특히 GBK 중국어 문서는
    CP949로도 디코딩되어 자동으로 구분할 수 없으므로 ``--encodings utf-8 gbk``처럼
    직접 지정해야 한다.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple, Union

from . import textutil
from .inventory import KIND_SYMLINK_CYCLE, iter_files

# 시그니처 판별과 같은 기본 목록을 쓴다. cp1252는 거의 모든 바이트를 받아들이므로 마지막.
DEFAULT_ENCODINGS: Tuple[str, ...] = textutil.DEFAULT_LEGACY_ENCODINGS
# 인코딩을 고를 때 보는 앞부분 크기.
DETECT_SAMPLE_BYTES = 64 * 1024
# 줄 나누기: 편집기처럼 \r\n, \n, \r에서만 나눈다(줄바꿈 문자를 줄 끝에 포함).
_LINE_RE = re.compile(r"[^\r\n]*(?:\r\n|\n|\r)|[^\r\n]+\Z")

# 거의 모든 바이트를 받아들이는 인코딩. 줄 단위로 읽을 때 앞으로 당기지 않고 항상 마지막에 둔다.
CATCH_ALL_ENCODINGS = frozenset({"cp1252", "latin-1", "latin1", "iso-8859-1"})
DEFAULT_INCLUDE_EXTS: Tuple[str, ...] = ("txt", "log", "csv", "json", "xml", "md", "ini", "conf", "reg")
DEFAULT_MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB

HIT_FIELDS: Tuple[str, ...] = (
    "path", "line_no", "match_span_start", "match_span_end", "matched", "pattern", "encoding", "line_preview",
)
SKIP_FIELDS: Tuple[str, ...] = ("path", "reason", "size_bytes")


def compile_patterns(
    keywords: Sequence[str],
    *,
    use_regex: bool = False,
    case_sensitive: bool = False,
) -> List["re.Pattern[str]"]:
    """검색어를 정규식 객체로 바꾼다.

    검색을 시작하기 전에 호출해, 잘못된 정규식을 파일을 다 읽은 뒤가 아니라
    처음에 오류로 알린다.

    Args:
        keywords: 검색어 목록.
        use_regex: True면 검색어를 정규식으로, False면 문자 그대로 찾는다.
        case_sensitive: 대소문자 구분 여부.

    Returns:
        컴파일된 패턴 목록.

    Raises:
        re.error: 정규식 문법이 잘못됐을 때.
    """
    flags = 0 if case_sensitive else re.IGNORECASE
    return [re.compile(kw if use_regex else re.escape(kw), flags) for kw in keywords]


def search_texts(
    root: Union[str, Path],
    keywords: Sequence[str],
    *,
    use_regex: bool = False,
    case_sensitive: bool = False,
    include_exts: Sequence[str] = DEFAULT_INCLUDE_EXTS,
    exclude_globs: Optional[Iterable[str]] = None,
    exclude_paths: Optional[Iterable[Union[str, Path]]] = None,
    follow_symlinks: bool = False,
    max_file_size_bytes: int = DEFAULT_MAX_FILE_SIZE,
    encodings: Sequence[str] = DEFAULT_ENCODINGS,
    preview_max_len: int = 240,
    skipped: Optional[List[Dict[str, object]]] = None,
) -> List[Dict[str, Union[str, int]]]:
    """텍스트 파일들을 줄 단위로 읽으며 검색어를 찾는다.

    한 줄에 같은 검색어가 여러 번 나오면 각각 한 건으로 기록한다. 결과의 ``encoding``
    열에는 그 줄을 읽은 인코딩을 기록한다(한 파일 안에서 줄마다 다를 수 있다).

    Args:
        root: 검색할 루트 폴더.
        keywords: 검색어 목록.
        use_regex: 검색어를 정규식으로 처리할지 여부.
        case_sensitive: 대소문자 구분 여부.
        include_exts: 검색 대상 확장자(점 없이, 예: ``"txt"``).
        exclude_globs: 제외할 글롭 패턴.
        exclude_paths: 통째로 제외할 폴더·파일 경로(결과 폴더 등).
        follow_symlinks: 심볼릭 링크를 따라갈지 여부. False면 링크는 건너뛰고 기록한다.
        max_file_size_bytes: 이보다 큰 파일은 건너뛰고 기록한다.
        encodings: BOM이 없을 때 시도할 인코딩 목록. 모듈 설명 참고.
        preview_max_len: 미리보기 최대 길이.
        skipped: 검색하지 못한 파일을 ``{"path", "reason", "size_bytes"}``로 기록할
            리스트. 이유는 ``symlink`` / ``too_large`` / ``read_error`` /
            ``dir_read_error`` / ``symlink_cycle`` 중 하나다.

    Returns:
        검색 결과 행 리스트. 열은 ``HIT_FIELDS``다.

    Raises:
        re.error: 정규식 문법이 잘못됐을 때.

    Example:
        >>> hits = search_texts("ForensicTestData", ["비밀번호"])
        >>> sorted({h["encoding"] for h in hits})  # doctest: +SKIP
        ['cp949', 'utf-16']
    """
    if not keywords:
        return []
    patterns = compile_patterns(keywords, use_regex=use_regex, case_sensitive=case_sensitive)
    wanted = {e.lower().lstrip(".") for e in include_exts}
    dir_errors: List[Dict[str, str]] = []
    rows: List[Dict[str, Union[str, int]]] = []

    for fpath, is_link in iter_files(
        Path(root).resolve(), follow_symlinks=follow_symlinks, exclude_globs=exclude_globs,
        exclude_paths=exclude_paths, errors=dir_errors,
    ):
        if fpath.suffix.lower().lstrip(".") not in wanted:
            continue
        if is_link and not follow_symlinks:
            _skip(skipped, fpath, "symlink", "")
            continue
        try:
            size = os.stat(fpath).st_size
        except OSError:
            _skip(skipped, fpath, "read_error", "")
            continue
        if size > max_file_size_bytes:
            _skip(skipped, fpath, "too_large", size)
            continue

        decoded = decode_text_lines(fpath, encodings=encodings)
        if decoded is None:
            _skip(skipped, fpath, "read_error", size)
            continue

        for lineno, (line, used_encoding) in enumerate(decoded, start=1):
            display_line = line.rstrip("\r\n")
            for pat in patterns:
                for m in pat.finditer(display_line):
                    if m.start() == m.end():
                        continue  # 빈 문자열 일치(예: 정규식 "^")는 의미가 없어 제외
                    rows.append({
                        "path": str(fpath),
                        "line_no": lineno,
                        "match_span_start": m.start(),
                        "match_span_end": m.end(),
                        "matched": m.group(0),
                        "pattern": pat.pattern,
                        "encoding": used_encoding,
                        "line_preview": _shrink(display_line, m.start(), m.end(), max_len=preview_max_len),
                    })

    if skipped is not None:
        for e in dir_errors:
            reason = "symlink_cycle" if e.get("kind") == KIND_SYMLINK_CYCLE else "dir_read_error"
            skipped.append({"path": e["path"], "reason": reason, "size_bytes": ""})
    return rows


def decode_text_file(path: Path, *, encodings: Sequence[str] = DEFAULT_ENCODINGS) -> Optional[Tuple[List[str], str]]:
    """파일 전체를 디코딩해 줄 목록과 사용한 인코딩을 반환한다.

    줄마다 인코딩이 다를 수 있으므로, 검색에는 줄별 인코딩을 주는 ``decode_text_lines``를
    쓴다. 이 함수는 파일 단위로 결과를 확인할 때 쓰는 요약 버전이다.

    Args:
        path: 읽을 파일 경로.
        encodings: 시도할 인코딩 목록(우선순위 순).

    Returns:
        ``(줄 리스트, 인코딩 이름)``. 줄마다 인코딩이 다르면 ``mixed(utf-8,cp949)``처럼
        쓰인 인코딩을 모두 적는다. 파일을 읽지 못하면 None.

    Example:
        >>> lines, enc = decode_text_file(Path("ForensicTestData/docs/memo_utf16.txt"))
        >>> enc
        'utf-16'
    """
    decoded = decode_text_lines(path, encodings=encodings)
    if decoded is None:
        return None
    used = list(dict.fromkeys(enc for _, enc in decoded))
    label = used[0] if len(used) == 1 else ("empty" if not used else f"mixed({','.join(used)})")
    return [line for line, _ in decoded], label


def decode_text_lines(path: Path, *, encodings: Sequence[str] = DEFAULT_ENCODINGS) -> Optional[List[Tuple[str, str]]]:
    """파일을 읽어 ``(줄, 그 줄의 인코딩)`` 목록으로 반환한다. 디코딩 오류로 예외가 나지 않는다.

    텍스트 모드로 ``open``만 해서는 디코딩이 일어나지 않고, 읽는 순간 일어난다.
    그래서 바이트를 먼저 전부 읽은 뒤 디코딩한다(호출 측에서 크기 상한을 건다).
    처리 순서는 모듈 설명을 참고한다.

    Args:
        path: 읽을 파일 경로.
        encodings: 시도할 인코딩 목록(우선순위 순).

    Returns:
        ``(줄 문자열, 인코딩 이름)`` 리스트. 빈 파일이면 빈 리스트, 읽지 못하면 None.

    Example:
        >>> [enc for _, enc in decode_text_lines(Path("ForensicTestData/docs/memo_cp949.txt"))]
        ['cp949', 'cp949']
    """
    try:
        raw = path.read_bytes()
    except OSError:
        return None
    if not raw:
        return []

    enc = textutil.detect_text_encoding(raw[:DETECT_SAMPLE_BYTES], legacy_encodings=encodings)
    if enc is not None and enc.startswith(("utf-8", "utf-16", "utf-32")):
        try:
            return [(line, enc) for line in split_lines(raw.decode(enc))]
        except UnicodeDecodeError:
            pass
    if enc is not None and enc.startswith(("utf-16", "utf-32")):
        text = raw.decode(enc, errors="replace")
        return [(line, f"{enc}+replace") for line in split_lines(text)]

    return _decode_per_line(raw, _legacy_base_encoding(raw, encodings), encodings)


def split_lines(text: str) -> List[str]:
    """문자열을 편집기와 같은 기준(``\\r\\n``, ``\\n``, ``\\r``)으로 나눈다. 줄바꿈 문자는 줄 끝에 남긴다.

    Args:
        text: 나눌 문자열.

    Returns:
        줄 리스트. 빈 문자열이면 빈 리스트.

    Example:
        >>> split_lines("a\\x0cb\\nc\\r\\nd")
        ['a\\x0cb\\n', 'c\\r\\n', 'd']
    """
    return _LINE_RE.findall(text)


def _legacy_base_encoding(raw: bytes, encodings: Sequence[str]) -> str:
    """UTF-8로 읽히지 않는 줄만 모아 파일의 대표 레거시 인코딩을 판정한다.

    UTF-8 줄과 CP949 줄이 섞인 파일을 통째로 판정하면, UTF-8 줄 때문에 CP949 디코딩이
    실패하고 CP949 한글도 받아들이는 GBK가 대신 뽑힌다. UTF-8이 아닌 줄만 보면 CP949
    줄만 남으므로 정확히 판정된다.

    Args:
        raw: 파일 바이트.
        encodings: 시도할 인코딩 목록.

    Returns:
        대표 레거시 인코딩. 판정하지 못하면 앞에서부터 가장 멀리 정상 디코딩되는 인코딩.

    Example:
        >>> mixed = ("A 비밀번호\\n".encode("utf-8") + "B 비밀번호\\n".encode("cp949")) * 5
        >>> _legacy_base_encoding(mixed, ["utf-8", "cp949", "gbk"])
        'cp949'
    """
    sample = bytearray()
    for chunk in raw.splitlines(keepends=True):
        try:
            chunk.decode("utf-8")
        except UnicodeDecodeError:
            sample += chunk
            if len(sample) >= DETECT_SAMPLE_BYTES:
                break
    legacy = [e for e in encodings if e.lower().replace("_", "-") not in ("utf-8", "utf8")]
    if sample and legacy:
        enc = textutil.detect_text_encoding(bytes(sample), legacy_encodings=legacy)
        if enc is not None and not enc.startswith(("utf-16", "utf-32")):
            return enc
        return _pick_encoding_for_broken(bytes(sample), legacy)
    return _pick_encoding_for_broken(raw, encodings)


def _decode_per_line(raw: bytes, base: str, encodings: Sequence[str]) -> List[Tuple[str, str]]:
    """바이트를 줄 단위로 나눠, 줄마다 엄격하게 디코딩되는 인코딩으로 읽는다.

    Args:
        raw: 파일 바이트(ASCII 호환 인코딩이어야 한다. UTF-16·UTF-32는 호출하지 않는다).
        base: 파일 전체에서 가장 그럴듯한 인코딩. UTF-8 다음으로 먼저 시도하고(CP1252 같은
            포괄 인코딩이면 당기지 않음), 어떤 인코딩으로도 안 되는 줄은 이 인코딩의
            대체 모드로 읽는다.
        encodings: 시도할 인코딩 목록.

    Returns:
        ``(줄 문자열, 인코딩 이름)`` 리스트. 대체 모드로 읽은 줄은 ``<base>+replace``.

    Example:
        >>> _decode_per_line("가\\n".encode("utf-8") + "나\\n".encode("cp949"), "utf-8", ["utf-8", "cp949"])
        [('가\\n', 'utf-8'), ('나\\n', 'cp949')]
    """
    promoted = [base] if base.lower() not in CATCH_ALL_ENCODINGS else []
    rest = [e for e in encodings if e.lower() not in CATCH_ALL_ENCODINGS]
    catch_all = [e for e in encodings if e.lower() in CATCH_ALL_ENCODINGS]
    order = list(dict.fromkeys(
        (["utf-8"] if "utf-8" in encodings else []) + promoted + rest + catch_all
    ))
    out: List[Tuple[str, str]] = []
    for chunk in raw.splitlines(keepends=True):
        for e in order:
            try:
                out.append((chunk.decode(e), e))
                break
            except (UnicodeDecodeError, LookupError):
                continue
        else:
            out.append((chunk.decode(base, errors="replace"), f"{base}+replace"))
    return out


def _valid_prefix_len(raw: bytes, encoding: str) -> int:
    """파일 앞에서부터 엄격 모드로 정상 디코딩되는 바이트 수를 구한다.

    Args:
        raw: 파일 바이트.
        encoding: 인코딩 이름.

    Returns:
        처음으로 디코딩 오류가 나는 위치(바이트). 끝까지 되면 전체 길이. 모르는 인코딩이면 -1.
    """
    try:
        raw.decode(encoding)
        return len(raw)
    except UnicodeDecodeError as e:
        return e.start
    except LookupError:
        return -1


def _pick_encoding_for_broken(raw: bytes, encodings: Sequence[str]) -> str:
    """일부가 깨진 파일을 읽을 인코딩을 고른다.

    "깨진 글자 수가 가장 적은 인코딩"으로 고르면 안 된다. CP949는 무작위 바이트 두 개를
    한 글자로 묶어 받아들이는 경우가 많아, 바이너리 구간에서 깨진 글자가 오히려 적게
    나오기 때문이다(그러면 앞부분의 UTF-8 한글이 CP949로 잘못 읽혀 검색되지 않는다).
    그래서 파일 앞에서부터 **얼마나 멀리까지 정상적으로 읽히는지**를 기준으로 삼고,
    가장 긴 것의 90% 이상이면 목록 앞쪽(사용자 우선순위)을 고른다.

    Args:
        raw: 파일 바이트.
        encodings: 후보 인코딩(우선순위 순).

    Returns:
        고른 인코딩 이름. 후보가 모두 쓸 수 없으면 ``utf-8``.
    """
    lengths = [(enc, _valid_prefix_len(raw, enc)) for enc in encodings]
    lengths = [(enc, n) for enc, n in lengths if n >= 0]
    if not lengths:
        return "utf-8"
    longest = max(n for _, n in lengths)
    for enc, n in lengths:
        if n >= longest * 0.9:
            return enc
    return lengths[0][0]


def _skip(skipped: Optional[List[Dict[str, object]]], path: Path, reason: str, size: object) -> None:
    """검색하지 못한 파일을 기록한다.

    Args:
        skipped: 기록할 리스트. None이면 아무것도 하지 않는다.
        path: 파일 경로.
        reason: 건너뛴 이유.
        size: 파일 크기(모르면 빈 문자열).
    """
    if skipped is not None:
        skipped.append({"path": str(path), "reason": reason, "size_bytes": size})


def _shrink(line: str, start: int, end: int, *, max_len: int = 240) -> str:
    """긴 줄을 일치 구간이 가운데 오도록 잘라 미리보기를 만든다.

    Args:
        line: 원본 줄.
        start: 일치 시작 위치.
        end: 일치 끝 위치.
        max_len: 미리보기 최대 길이.

    Returns:
        미리보기 문자열. 잘린 쪽에는 ``…``를 붙인다.
    """
    if len(line) <= max_len:
        return line
    center = (start + end) // 2
    left = max(0, center - max_len // 2)
    right = min(len(line), left + max_len)
    left = max(0, right - max_len)
    return f"{'…' if left > 0 else ''}{line[left:right]}{'…' if right < len(line) else ''}"
