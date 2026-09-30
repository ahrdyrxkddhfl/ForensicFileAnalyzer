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

import mimetypes
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

# 같은 컨테이너 형식을 공유해서 "불일치"로 보면 안 되는 확장자 묶음.
# 예: DOCX·XLSX·APK·IPA는 내부 구조가 전부 ZIP이다.
_TEXT_FAMILY: FrozenSet[str] = frozenset({
    ".txt", ".log", ".csv", ".tsv", ".json", ".xml", ".md",
    ".ini", ".conf", ".cfg", ".yaml", ".yml",
})
_EXTRA_ALLOWED_EXTS: Dict[str, FrozenSet[str]] = {
    "text/plain": _TEXT_FAMILY,
    "application/zip": frozenset({
        ".zip", ".docx", ".xlsx", ".pptx", ".jar", ".apk", ".ipa", ".odt",
    }),
    "application/vnd.sqlite3": frozenset({".sqlite", ".sqlite3", ".db"}),
    "application/x-sqlite3": frozenset({".sqlite", ".sqlite3", ".db"}),
    "application/x-ole-storage": frozenset({".doc", ".xls", ".ppt", ".msg"}),
    "application/cdfv2": frozenset({".doc", ".xls", ".ppt", ".msg"}),
    "application/x-bplist": frozenset({".plist"}),
    "image/jpeg": frozenset({".jpg"}),
}

# 형식을 확정할 수 없어 불일치 판정을 하지 않는 MIME.
_UNDETERMINED_MIMES: FrozenSet[str] = frozenset({
    "", "application/octet-stream", "inode/x-empty", "application/x-empty",
})

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

    Example:
        >>> probe_file_type("ForensicTestData/images/mismatch_signature.jpg")["real_mime"]
        'image/png'
    """
    path = Path(path)
    if not path.is_file():
        return None

    if prefer_magic and _HAS_MAGIC:
        try:
            mime = magic.from_file(str(path), mime=True) or ""
            desc = magic.from_file(str(path), mime=False) or ""
            if mime:
                return {
                    "real_mime": mime,
                    "real_ext": _ext_from_mime(mime),
                    "description": desc,
                    "source": "libmagic",
                }
        except Exception:
            pass  # libmagic 오류 시 내장 판별로 넘어간다.

    try:
        with path.open("rb") as f:
            head = f.read(_HEADER_READ_BYTES)
    except OSError:
        return None

    return _probe_header(head)


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
            row["ext_mismatch"] = False
            continue

        row[f"{sig_prefix}mime"] = result["real_mime"] or missing_as
        row[f"{sig_prefix}ext"] = result["real_ext"] or missing_as
        row[f"{sig_prefix}desc"] = result["description"] or missing_as
        row[f"{sig_prefix}source"] = result["source"]
        row["ext_mismatch"] = _is_ext_mismatch(
            disk_ext, result["real_mime"], result["real_ext"]
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
    allowed = {_normalize_ext(e) for e in mimetypes.guess_all_extensions(mime)}
    if real_ext:
        allowed.add(_normalize_ext(real_ext))
    allowed |= _EXTRA_ALLOWED_EXTS.get(mime, frozenset())
    if mime.startswith("text/"):
        allowed |= _TEXT_FAMILY  # text/csv, text/x-log 등 세부 판별 차이를 흡수
    allowed.discard("")
    return frozenset(allowed)


def _is_ext_mismatch(disk_ext: str, real_mime: str, real_ext: str) -> bool:
    """디스크상 확장자가 실제 형식과 어긋나는지 판정한다.

    판정 규칙:
        - 형식을 확정할 수 없으면(빈 파일, 알 수 없는 바이너리) False.
        - 허용 확장자 집합을 만들 수 없으면 False(보수적으로 일치 처리).
        - 확장자가 없는 텍스트 파일(README 등)은 False.
        - 확장자가 없는 비텍스트 파일은 True(형식 은닉 의심).
        - 그 외에는 허용 집합에 없으면 True.

    Args:
        disk_ext: 디스크상 확장자.
        real_mime: 판별된 MIME.
        real_ext: 판별된 대표 확장자.

    Returns:
        불일치이면 True.

    Example:
        >>> _is_ext_mismatch(".jpg", "image/png", ".png")
        True
        >>> _is_ext_mismatch(".log", "text/plain", ".txt")
        False
        >>> _is_ext_mismatch(".apk", "application/zip", ".zip")
        False
    """
    if real_mime in _UNDETERMINED_MIMES:
        return False
    allowed = _allowed_exts(real_mime, real_ext)
    if not allowed:
        return False
    d = _normalize_ext(disk_ext)
    if not d:
        return not real_mime.startswith("text/")
    return d not in allowed
