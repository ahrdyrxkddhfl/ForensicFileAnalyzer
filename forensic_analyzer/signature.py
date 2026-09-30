# forensic_analyzer/signature.py
"""파일 시그니처(매직 넘버) 기반 실제 파일 형식 판별 모듈.

확장자가 아니라 파일 앞부분의 실제 바이트를 읽어 형식을 판별하고,
디스크상 확장자와 비교해 위장 파일(예: .jpg로 이름만 바꾼 PNG)을 찾아낸다.

판별 순서:
    1. python-magic(libmagic)이 설치되어 있으면 libmagic 결과를 사용한다.
    2. 없거나 실패하면 이 모듈에 정의한 매직 넘버 표(_SIGNATURES)로 직접 판별한다.
    3. 표에도 없으면 NUL 바이트 유무로 텍스트/바이너리만 구분한다.

어느 경우에도 확장자 기반 추측(mimetypes.guess_type)은 사용하지 않는다.
확장자로 형식을 추측하면 확장자 위장을 절대 탐지할 수 없기 때문이다.

Example:
    >>> rows = [{"path": "ForensicTestData/images/mismatch_signature.jpg"}]
    >>> add_signature_to_rows(rows)[0]["ext_mismatch"]
    True
"""
from __future__ import annotations

import math
import mimetypes
import os  # noqa: F401  (독스트링 예제에서 os.urandom 사용)
from collections import Counter
from pathlib import Path
from typing import Dict, FrozenSet, List, Optional, Tuple, Union

try:
    import magic  # type: ignore
    _HAS_MAGIC = True
except Exception:  # ImportError, 또는 libmagic 공유 라이브러리 로드 실패(OSError)
    _HAS_MAGIC = False


# 헤더 판별에 읽을 바이트 수. 텍스트/바이너리 휴리스틱에도 같은 버퍼를 쓴다.
_HEADER_READ_BYTES = 8192

# (오프셋, 매직 바이트, MIME, 대표 확장자) 표. 긴 시그니처를 먼저 둬서 오판을 줄인다.
_SIGNATURES: Tuple[Tuple[int, bytes, str, str], ...] = (
    (0, b"\x89PNG\r\n\x1a\n", "image/png", ".png"),
    (0, b"SQLite format 3\x00", "application/vnd.sqlite3", ".sqlite"),
    (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "application/x-ole-storage", ".doc"),
    (0, b"GIF87a", "image/gif", ".gif"),
    (0, b"GIF89a", "image/gif", ".gif"),
    (0, b"%PDF-", "application/pdf", ".pdf"),
    (0, b"PK\x03\x04", "application/zip", ".zip"),
    (0, b"PK\x05\x06", "application/zip", ".zip"),  # 빈 ZIP
    (0, b"PK\x07\x08", "application/zip", ".zip"),  # 분할 ZIP
    (0, b"bplist00", "application/x-bplist", ".plist"),  # iOS 바이너리 plist
    (0, b"\xff\xd8\xff", "image/jpeg", ".jpg"),
    (0, b"\x1f\x8b", "application/gzip", ".gz"),
)

# 내부 구조가 ZIP / OLE(복합 문서)인 형식 묶음. 한컴 HWP(5.x)는 OLE, HWPX는 ZIP이다.
_ZIP_FAMILY: FrozenSet[str] = frozenset({
    ".zip", ".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm",
    ".odt", ".ods", ".odp", ".hwpx", ".epub", ".jar", ".apk", ".aar", ".ipa",
})
_OLE_FAMILY: FrozenSet[str] = frozenset({
    ".doc", ".xls", ".ppt", ".msg", ".hwp", ".msi",
    ".db",  # Windows 썸네일 캐시 Thumbs.db는 OLE 형식이다.
})

# 같은 컨테이너 형식을 공유해서 "불일치"로 보면 안 되는 확장자 묶음.
# 예: DOCX·XLSX·APK·IPA는 내부 구조가 전부 ZIP이다.
_TEXT_FAMILY: FrozenSet[str] = frozenset({
    # 문서·데이터
    ".txt", ".log", ".csv", ".tsv", ".json", ".xml", ".md",
    ".ini", ".conf", ".cfg", ".yaml", ".yml", ".toml", ".srt", ".vtt",
    # 웹·스크립트·소스 코드(내용이 전부 일반 텍스트)
    ".html", ".css", ".js", ".ts", ".py", ".sh", ".bat", ".ps1",
    ".sql", ".java", ".kt", ".c", ".h", ".cpp", ".go", ".rs", ".rb", ".php",
})
_EXTRA_ALLOWED_EXTS: Dict[str, FrozenSet[str]] = {
    "text/plain": _TEXT_FAMILY,
    "application/zip": _ZIP_FAMILY,
    "application/vnd.sqlite3": frozenset({".sqlite", ".sqlite3", ".db"}),
    "application/x-sqlite3": frozenset({".sqlite", ".sqlite3", ".db"}),
    "application/x-ole-storage": _OLE_FAMILY,
    "application/cdfv2": _OLE_FAMILY,
    "application/vnd.ms-office": _OLE_FAMILY,
    "application/x-hwp": frozenset({".hwp"}),
    "application/x-bplist": frozenset({".plist"}),
    "image/jpeg": frozenset({".jpg"}),
}

# 빈 파일. 내용이 없으므로 어떤 확장자와도 모순되지 않는다.
_EMPTY_MIMES: FrozenSet[str] = frozenset({"inode/x-empty", "application/x-empty"})

# 시그니처로 형식을 확정하지 못한 경우(알 수 없는 바이너리).
_UNKNOWN_BINARY_MIMES: FrozenSet[str] = frozenset({"", "application/octet-stream"})

# 정상 파일이라면 반드시 알려진 시그니처로 시작하는 확장자.
# 이 확장자인데 시그니처가 없다면 헤더 훼손이나 위장을 의심한다. 예: 헤더가 지워진 photo.png
_SIGNATURE_REQUIRED_EXTS: FrozenSet[str] = frozenset(
    (_ZIP_FAMILY | _OLE_FAMILY | {".png", ".jpg", ".gif", ".pdf", ".sqlite", ".sqlite3", ".gz"})
    - {".db"}  # .db는 SQLite 외에도 형식이 제각각이라 시그니처를 강제하지 않는다.
)

# 텍스트 확장자인데 내용을 텍스트로 확정하지 못했을 때, 암호화·무작위 데이터로 볼 기준.
# 섀넌 엔트로피(바이트당 비트, 최대 8)로 판단한다. 실측값 예시:
#   UTF-8/latin-1/Shift-JIS/BOM 없는 UTF-16 텍스트, NUL로 채워진 로그 → 2.4 ~ 4.3
#   무작위·암호화 데이터 → 7.9 이상
# 표본이 너무 작으면 엔트로피가 낮게 나와 판단할 수 없으므로 최소 크기를 둔다.
_HIGH_ENTROPY_BITS = 7.0
_ENTROPY_MIN_BYTES = 256

_KNOWN_EXT_NORMALIZE = {
    ".jpe": ".jpg",
    ".jpeg": ".jpg",
    ".tif": ".tiff",
    ".htm": ".html",
}


def probe_file_type(
    path: Union[str, Path],
    *,
    prefer_magic: bool = True,
) -> Optional[Dict[str, str]]:
    """파일의 실제 바이트를 읽어 MIME 형식과 설명을 판별한다.

    Args:
        path: 판별할 파일 경로.
        prefer_magic: True이고 python-magic이 설치되어 있으면 libmagic을 우선 사용한다.
            False이면 항상 내장 매직 넘버 표로 판별한다.

    Returns:
        판별 결과 딕셔너리. 파일을 읽을 수 없으면 None.

        - ``real_mime`` (str): 판별된 MIME. 판별 불가 시 ``application/octet-stream``.
        - ``real_ext`` (str): MIME의 대표 확장자(예: ``.png``). 모르면 빈 문자열.
        - ``description`` (str): 사람이 읽을 수 있는 설명.
        - ``source`` (str): 판별 근거. ``libmagic`` / ``header`` / ``heuristic``.
        - ``high_entropy`` (str): 앞부분 엔트로피가 기준 이상이면 ``"1"``, 아니면 ``""``.

    Example:
        >>> probe_file_type("ForensicTestData/images/mismatch_signature.jpg")["real_mime"]
        'image/png'
    """
    path = Path(path)
    if not path.is_file():
        return None

    head = _read_head(path)
    high_entropy = "1" if _is_high_entropy(head) else ""

    if prefer_magic and _HAS_MAGIC:
        try:
            mime = magic.from_file(str(path), mime=True) or ""
            desc = magic.from_file(str(path), mime=False) or ""
            if mime and mime.lower() != "application/octet-stream":
                return {
                    "real_mime": mime,
                    "real_ext": _ext_from_mime(mime),
                    "description": desc,
                    "source": "libmagic",
                    "high_entropy": high_entropy,
                }
        except Exception:
            pass  # libmagic 오류 시 내장 판별로 넘어간다.
        # libmagic이 octet-stream으로 포기한 경우에도 내장 표(BOM, HWP 등)로 한 번 더 확인한다.

    result = _probe_header(head)
    result["high_entropy"] = high_entropy
    return result


def add_signature_to_rows(
    rows: List[Dict[str, object]],
    *,
    prefer_magic: bool = True,
    disk_ext_field: str = "ext_on_disk",
    sig_prefix: str = "sig_",
    missing_as: str = "",
) -> List[Dict[str, object]]:
    """인벤토리 행마다 시그니처 판별 결과와 확장자 불일치 여부를 추가한다.

    Args:
        rows: ``collect_inventory`` 결과. 각 행에 ``path`` 키가 있어야 한다.
        prefer_magic: libmagic 우선 사용 여부. ``probe_file_type`` 참고.
        disk_ext_field: 디스크상 확장자를 기록할 열 이름.
        sig_prefix: 추가할 시그니처 열의 접두어.
        missing_as: 판별 실패 시 채울 값.

    Returns:
        입력 ``rows``를 제자리에서 수정해 그대로 반환한다. 추가되는 열은 다음과 같다.

        - ``{sig_prefix}mime``: 실제 MIME (예: ``image/png``)
        - ``{sig_prefix}ext``: 시그니처 기준 대표 확장자 (예: ``.png``)
        - ``{sig_prefix}desc``: 판별 설명
        - ``{sig_prefix}source``: 판별 근거 (``libmagic`` / ``header`` / ``heuristic``)
        - ``{sig_prefix}high_entropy``: 앞부분이 무작위·암호화 수준의 엔트로피이면 True
        - ``{disk_ext_field}``: 디스크상 확장자
        - ``ext_mismatch``: 확장자와 실제 형식이 다르면 True

    Example:
        >>> rows = add_signature_to_rows([{"path": "a.jpg"}])  # 실제로는 PNG인 파일
        >>> rows[0]["sig_mime"], rows[0]["ext_mismatch"]
        ('image/png', True)
    """
    for row in rows:
        p = row.get("path")
        disk_ext = _disk_extension(str(p)) if p else ""
        result = probe_file_type(p, prefer_magic=prefer_magic) if p else None

        row[disk_ext_field] = disk_ext or missing_as
        if result is None:
            row[f"{sig_prefix}mime"] = missing_as
            row[f"{sig_prefix}ext"] = missing_as
            row[f"{sig_prefix}desc"] = missing_as
            row[f"{sig_prefix}source"] = missing_as
            row[f"{sig_prefix}high_entropy"] = False
            row["ext_mismatch"] = False
            continue

        row[f"{sig_prefix}mime"] = result["real_mime"] or missing_as
        row[f"{sig_prefix}ext"] = result["real_ext"] or missing_as
        row[f"{sig_prefix}desc"] = result["description"] or missing_as
        row[f"{sig_prefix}source"] = result["source"]
        row[f"{sig_prefix}high_entropy"] = bool(result.get("high_entropy"))
        row["ext_mismatch"] = _is_ext_mismatch(
            disk_ext, result["real_mime"], result["real_ext"],
            high_entropy=bool(result.get("high_entropy")),
        )
    return rows


# ---------------------------------------------------------------------------
# 내부 유틸
# ---------------------------------------------------------------------------

def _probe_header(head: bytes) -> Dict[str, str]:
    """파일 앞부분 바이트만으로 형식을 판별한다(libmagic 미사용 경로).

    Args:
        head: 파일 앞부분 바이트(최대 ``_HEADER_READ_BYTES``).

    Returns:
        ``probe_file_type``과 같은 형태의 딕셔너리.
    """
    if not head:
        return {"real_mime": "inode/x-empty", "real_ext": "",
                "description": "empty", "source": "header"}

    if _is_bom_text(head):
        return {"real_mime": "text/plain", "real_ext": ".txt",
                "description": "text with BOM (UTF-8/16/32)", "source": "header"}

    for offset, sig, mime, ext in _SIGNATURES:
        if head[offset:offset + len(sig)] == sig:
            return {"real_mime": mime, "real_ext": ext,
                    "description": f"magic number match ({sig[:8]!r})",
                    "source": "header"}

    if b"\x00" not in head and _decodes_as_text(head):
        return {"real_mime": "text/plain", "real_ext": ".txt",
                "description": "text (no NUL byte)", "source": "heuristic"}

    return {"real_mime": "application/octet-stream", "real_ext": "",
            "description": "unknown binary", "source": "heuristic"}


def _is_bom_text(head: bytes) -> bool:
    """BOM으로 시작하고, 실제로 그 인코딩의 정상 텍스트인지 확인한다.

    BOM 2~4바이트만 보고 텍스트로 인정하면, 무작위 바이트 앞에 ``FF FE``만 붙여
    위장 판정을 피할 수 있다. 그래서 BOM이 가리키는 인코딩으로 실제 디코딩이
    되는지, 엔트로피가 텍스트 수준인지까지 확인한다.

    Args:
        head: 파일 앞부분 바이트.

    Returns:
        정상적인 BOM 텍스트이면 True.

    Example:
        >>> _is_bom_text("메모".encode("utf-16"))
        True
        >>> _is_bom_text(b"\\xff\\xfe" + os.urandom(4096))
        False
    """
    candidates = (
        (b"\xff\xfe\x00\x00", "utf-32", 4),
        (b"\x00\x00\xfe\xff", "utf-32", 4),
        (b"\xef\xbb\xbf", "utf-8-sig", 1),
        (b"\xff\xfe", "utf-16", 2),
        (b"\xfe\xff", "utf-16", 2),
    )
    for bom, enc, unit in candidates:
        if not head.startswith(bom):
            continue
        body = head[: len(head) - (len(head) % unit)]
        # 읽기 버퍼 끝에서 문자가 잘렸을 수 있으므로 마지막 한 문자분은 잘라 가며 재시도한다.
        for cut in (0, unit, unit * 2, 3):
            try:
                (body[:-cut] if cut else body).decode(enc)
                break
            except UnicodeDecodeError:
                continue
        else:
            return False
        return not _is_high_entropy(head)
    return False


def _shannon_entropy(buf: bytes) -> float:
    """바이트열의 섀넌 엔트로피(바이트당 비트, 0~8)를 계산한다.

    값이 8에 가까울수록 바이트가 고르게 분포한다(무작위·암호화·압축 데이터).
    사람이 읽는 텍스트는 쓰는 문자가 한정되어 있어 훨씬 낮다.

    Args:
        buf: 계산할 바이트열.

    Returns:
        엔트로피 값. 빈 입력이면 0.0.

    Example:
        >>> round(_shannon_entropy(b"aaaa"), 2)
        0.0
        >>> _shannon_entropy(os.urandom(4096)) > 7.9
        True
    """
    if not buf:
        return 0.0
    n = len(buf)
    return -sum(c / n * math.log2(c / n) for c in Counter(buf).values())


def _is_high_entropy(buf: bytes) -> bool:
    """표본이 충분히 크고 엔트로피가 기준 이상이면 True를 반환한다.

    Args:
        buf: 파일 앞부분 바이트.

    Returns:
        ``_ENTROPY_MIN_BYTES`` 이상이고 엔트로피가 ``_HIGH_ENTROPY_BITS`` 이상이면 True.
    """
    return len(buf) >= _ENTROPY_MIN_BYTES and _shannon_entropy(buf) >= _HIGH_ENTROPY_BITS


def _read_head(path: Union[str, Path]) -> bytes:
    """파일 앞부분을 ``_HEADER_READ_BYTES``만큼 읽는다. 실패하면 빈 바이트열.

    Args:
        path: 파일 경로.

    Returns:
        읽은 바이트열.
    """
    try:
        with Path(path).open("rb") as f:
            return f.read(_HEADER_READ_BYTES)
    except OSError:
        return b""


def _decodes_as_text(buf: bytes) -> bool:
    """버퍼가 UTF-8 또는 CP949 텍스트로 해석되는지 확인한다.

    읽기 버퍼 끝에서 멀티바이트 문자가 잘릴 수 있으므로 마지막 3바이트까지는
    잘라내며 재시도한다.

    Args:
        buf: 검사할 바이트열.

    Returns:
        두 인코딩 중 하나로 디코딩되면 True.
    """
    for enc in ("utf-8", "cp949"):
        for cut in range(4):
            try:
                (buf[:-cut] if cut else buf).decode(enc)
                return True
            except UnicodeDecodeError:
                continue
    return False


def _normalize_ext(ext: str) -> str:
    """확장자를 소문자·점 포함 형태로 맞추고 동의어를 통일한다.

    Args:
        ext: ``JPEG``, ``.jpeg``, ``jpg`` 같은 확장자 문자열.

    Returns:
        정규화된 확장자(예: ``.jpg``). 빈 입력이면 빈 문자열.
    """
    ext = (ext or "").strip().lower()
    if not ext:
        return ""
    if not ext.startswith("."):
        ext = "." + ext
    return _KNOWN_EXT_NORMALIZE.get(ext, ext)


def _disk_extension(path: str) -> str:
    """경로에서 디스크상 확장자를 뽑아 정규화한다.

    Args:
        path: 파일 경로.

    Returns:
        정규화된 확장자. 확장자가 없으면 빈 문자열.
    """
    return _normalize_ext(Path(path).suffix)


def _ext_from_mime(mime: str) -> str:
    """MIME에서 대표 확장자를 추정한다.

    Args:
        mime: MIME 문자열.

    Returns:
        정규화된 대표 확장자. 알 수 없으면 빈 문자열.
    """
    if not mime:
        return ""
    return _normalize_ext(mimetypes.guess_extension(mime) or "")


def _allowed_exts(mime: str, real_ext: str) -> FrozenSet[str]:
    """해당 MIME으로 판별된 파일이 가져도 정상인 확장자 집합을 만든다.

    Args:
        mime: 판별된 MIME.
        real_ext: 판별된 대표 확장자.

    Returns:
        허용 확장자 집합. 비어 있으면 판정 불가를 뜻한다.
    """
    mime = mime.lower()
    allowed = {_normalize_ext(e) for e in mimetypes.guess_all_extensions(mime)}
    if real_ext:
        allowed.add(_normalize_ext(real_ext))
    allowed |= _EXTRA_ALLOWED_EXTS.get(mime, frozenset())
    if mime.startswith("text/"):
        allowed |= _TEXT_FAMILY  # text/csv, text/x-log 등 세부 판별 차이를 흡수
    allowed.discard("")
    return frozenset(allowed)


def _is_ext_mismatch(
    disk_ext: str,
    real_mime: str,
    real_ext: str,
    *,
    high_entropy: bool = False,
) -> bool:
    """디스크상 확장자가 실제 형식과 어긋나는지 판정한다.

    판정 규칙:
        - 빈 파일이면 False.
        - 실제 형식이 "알 수 없는 바이너리"일 때:
            * 확장자가 시그니처를 가져야 하는 형식(.png, .pdf, .zip, .hwp 등)이면 True.
              헤더 훼손이나 위장을 의심한다.
            * 확장자가 텍스트 계열이면, 엔트로피가 무작위·암호화 수준일 때만 True.
              latin-1·Shift-JIS·BOM 없는 UTF-16 텍스트나 NUL로 채워진 로그처럼
              내장 판별기가 텍스트로 확정하지 못한 정상 파일은 엔트로피가 낮아 False.
            * 그 밖의 확장자(.bin, .dat 등)는 False.
        - 형식이 판별됐는데 확장자가 없으면, 텍스트는 False(README 등), 그 외는 True.
        - 그 밖에는 허용 확장자 집합에 없으면 True.

    Args:
        disk_ext: 디스크상 확장자.
        real_mime: 판별된 MIME.
        real_ext: 판별된 대표 확장자.
        high_entropy: 파일 앞부분 엔트로피가 ``_HIGH_ENTROPY_BITS`` 이상인지 여부.

    Returns:
        불일치이면 True.

    Example:
        >>> _is_ext_mismatch(".jpg", "image/png", ".png")
        True
        >>> _is_ext_mismatch(".txt", "application/octet-stream", "", high_entropy=True)
        True
        >>> _is_ext_mismatch(".log", "application/octet-stream", "", high_entropy=False)
        False
        >>> _is_ext_mismatch(".png", "application/octet-stream", "")
        True
        >>> _is_ext_mismatch(".db", "application/x-ole-storage", ".doc")  # Thumbs.db
        False
    """
    mime = (real_mime or "").lower()
    d = _normalize_ext(disk_ext)

    if mime in _EMPTY_MIMES:
        return False
    if mime in _UNKNOWN_BINARY_MIMES:
        if d in _SIGNATURE_REQUIRED_EXTS:
            return True
        if d in _TEXT_FAMILY:
            return high_entropy
        return False

    allowed = _allowed_exts(mime, real_ext)
    if not allowed:
        return False
    if not d:
        return not mime.startswith("text/")
    return d not in allowed
