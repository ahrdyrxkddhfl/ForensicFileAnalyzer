# forensic_analyzer/signature.py
"""파일 시그니처(매직 넘버) 기반 실제 형식 판별과 확장자 위장 탐지.

확장자가 아니라 파일의 실제 바이트를 읽어 형식을 판별하고, 디스크상 확장자와
비교해 위장 파일을 찾는다. 예를 들어 이름만 ``photo.jpg``이고 내용은 PNG인 파일,
이름은 ``memo.txt``인데 내용은 텍스트가 아닌 파일을 찾아낸다.

판별 순서:
    0. ZIP(``PK``로 시작)이면 libmagic을 쓰지 않고 ZIP 안을 열어 APK·IPA·DOCX·HWPX
       등 내부 구조를 확인한다(``container.py``). libmagic의 ZIP 세부 판별은 버전마다
       다르고 무엇을 확인했는지 알 수 없어서, 직접 확인한 결과로 판정한다.
    1. python-magic(libmagic)이 설치되어 있으면 libmagic을 쓴다. libmagic이
       ``application/octet-stream``(모름)으로 포기하면 2번으로 넘어간다.
    2. 이 모듈의 매직 넘버 표(``SIGNATURES``)로 직접 판별한다.
    3. 표에 없으면 텍스트인지 판별한다(``textutil.detect_text_encoding``).
       BOM, UTF-8, CP949, Shift-JIS, GBK, CP1252, BOM 없는 UTF-16을 지원한다.
    4. 모두 아니면 "알 수 없는 바이너리"다.

어느 경우에도 확장자로 형식을 추측하지 않는다. 확장자로 추측하면 확장자 위장을
탐지할 수 없기 때문이다.

텍스트 파일 뒤에 숨긴 데이터:
    판별은 파일 앞부분을 기준으로 하므로, 앞에 평범한 텍스트를 두고 뒤에 암호화
    데이터를 붙이면 텍스트로 판정된다. 그래서 텍스트로 판정된 파일은 중간과 끝
    구간도 표본으로 읽어, 텍스트가 아닌 구간이 있으면 ``embedded_binary``로 표시하고
    텍스트 확장자라면 불일치로 판정한다.

Example:
    >>> rows = add_signature_to_rows([{"path": "ForensicTestData/images/mismatch_signature.jpg"}])
    >>> rows[0]["sig_mime"], rows[0]["ext_mismatch"]
    ('image/png', True)
"""
from __future__ import annotations

import mimetypes
from pathlib import Path
from typing import Dict, FrozenSet, List, Optional, Tuple, Union

from . import container, textutil

try:
    import magic  # type: ignore
    _HAS_MAGIC = True
except Exception:  # ImportError, 또는 libmagic 공유 라이브러리 로드 실패(OSError)
    _HAS_MAGIC = False

# 한 번에 읽는 표본 크기. 앞부분 판별과 중간·끝 구간 표본에 모두 쓴다.
SAMPLE_BYTES = 8192

# OS의 mime.types 설정 파일을 읽지 않는 독립 인스턴스. PC마다 결과가 달라지지 않게 한다.
_MIME_DB = mimetypes.MimeTypes()

# 같은 형식의 확장자 표기 차이를 하나로 통일한다.
_KNOWN_EXT_NORMALIZE = {".jpe": ".jpg", ".jpeg": ".jpg", ".tif": ".tiff", ".htm": ".html"}

# (오프셋, 매직 바이트, MIME, 대표 확장자). 긴 시그니처를 먼저 둬서 오판을 줄인다.
SIGNATURES: Tuple[Tuple[int, bytes, str, str], ...] = (
    (0, b"\x89PNG\r\n\x1a\n", "image/png", ".png"),
    (0, b"SQLite format 3\x00", "application/vnd.sqlite3", ".sqlite"),
    (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "application/x-ole-storage", ".doc"),
    (0, b"GIF87a", "image/gif", ".gif"),
    (0, b"GIF89a", "image/gif", ".gif"),
    (0, b"%PDF-", "application/pdf", ".pdf"),
    (0, b"PK\x03\x04", "application/zip", ".zip"),
    (0, b"PK\x05\x06", "application/zip", ".zip"),  # 빈 ZIP
    (0, b"PK\x07\x08", "application/zip", ".zip"),  # 분할 ZIP
    (0, b"bplist00", "application/x-bplist", ".plist"),  # iOS·macOS 바이너리 plist
    (0, b"\xff\xd8\xff", "image/jpeg", ".jpg"),
    (0, b"\x1f\x8b", "application/gzip", ".gz"),
    (0, b"7z\xbc\xaf\x27\x1c", "application/x-7z-compressed", ".7z"),
    (0, b"Rar!\x1a\x07", "application/vnd.rar", ".rar"),
    (0, b"\x7fELF", "application/x-executable", ""),          # 리눅스·안드로이드 실행 파일
    (0, b"fLaC", "audio/flac", ".flac"),
    (0, b"OggS", "audio/ogg", ".ogg"),
    (0, b"ID3", "audio/mpeg", ".mp3"),
    (0, b"II*\x00", "image/tiff", ".tiff"),
    (0, b"MM\x00*", "image/tiff", ".tiff"),
)
# "MZ"(윈도우 실행 파일)와 "BM"(BMP)은 2바이트뿐이라, 우연히 그 글자로 시작하는 텍스트를
# 오판할 수 있다. 그래서 표에 넣지 않고 ``_probe_bytes``에서 구조까지 확인한다.
_BMP_DIB_SIZES = frozenset({12, 40, 52, 56, 64, 108, 124})

# RIFF·ftyp 컨테이너는 오프셋 8의 형식 코드로 세부 형식을 가른다.
RIFF_FORMS: Dict[bytes, Tuple[str, str]] = {
    b"WEBP": ("image/webp", ".webp"), b"WAVE": ("audio/x-wav", ".wav"), b"AVI ": ("video/x-msvideo", ".avi"),
}
FTYP_BRANDS: Dict[bytes, Tuple[str, str]] = {
    b"heic": ("image/heic", ".heic"), b"heix": ("image/heic", ".heic"), b"mif1": ("image/heif", ".heif"),
    b"avif": ("image/avif", ".avif"), b"avis": ("image/avif", ".avif"),
    b"qt  ": ("video/quicktime", ".mov"), b"M4A ": ("audio/mp4", ".m4a"), b"M4V ": ("video/x-m4v", ".m4v"),
    b"3gp4": ("video/3gpp", ".3gp"), b"3gp5": ("video/3gpp", ".3gp"), b"3gp6": ("video/3gpp", ".3gp"),
    b"3g2a": ("video/3gpp2", ".3g2"), b"crx ": ("image/x-canon-cr3", ".cr3"),
}
# ftyp로 시작하는 ISO 기본 미디어 형식 계열. 브랜드가 수십 가지라 세부 형식끼리는
# 서로 바꿔 붙여도 불일치로 보지 않는다(모르는 브랜드는 video/mp4로 처리).
ISO_BMFF_FAMILY: FrozenSet[str] = frozenset({
    ".mp4", ".m4v", ".m4a", ".m4b", ".m4p", ".mov", ".qt", ".3gp", ".3g2",
    ".heic", ".heif", ".avif", ".avifs", ".f4v", ".cr3",
})
# TIFF 구조를 쓰는 카메라 RAW 형식(캐논·니콘·어도비 DNG·소니 등).
TIFF_FAMILY: FrozenSet[str] = frozenset({
    ".tiff", ".cr2", ".nef", ".nrw", ".dng", ".arw", ".srf", ".sr2", ".orf", ".rw2", ".pef", ".srw",
    ".3fr", ".erf", ".kdc", ".dcr", ".mos", ".iiq",
})

# 내용이 일반 텍스트인 확장자.
TEXT_FAMILY: FrozenSet[str] = frozenset({
    # 문서·데이터
    ".txt", ".log", ".csv", ".tsv", ".json", ".xml", ".md", ".reg",
    ".ini", ".conf", ".cfg", ".yaml", ".yml", ".toml", ".srt", ".vtt",
    ".plist", ".svg", ".rtf", ".eml", ".vcf", ".ics", ".mbox", ".properties",  # XML plist·메일·연락처·일정
    ".pem", ".key",  # 텍스트 인증서·키(.key는 맥 Keynote 문서와 겹치므로 ZIP 계열에도 둔다)
    # 웹·스크립트·소스 코드
    ".html", ".css", ".js", ".ts", ".py", ".sh", ".bat", ".ps1",
    ".sql", ".java", ".kt", ".c", ".h", ".cpp", ".go", ".rs", ".rb", ".php",
})

# 내부 구조가 ZIP / OLE(복합 문서)인 형식. 한컴 HWP(5.x)는 OLE, HWPX는 ZIP이다.
ZIP_FAMILY: FrozenSet[str] = frozenset({
    ".zip", ".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm",
    ".odt", ".ods", ".odp", ".odg", ".hwpx", ".epub", ".jar", ".war", ".ear",
    ".apk", ".aar", ".aab", ".apks", ".xapk", ".ipa",                 # 안드로이드·iOS 앱
    ".pages", ".numbers", ".key",                                      # 맥 iWork 문서
    ".whl", ".xpi", ".nupkg", ".vsix", ".appx", ".msix",               # 패키지
    ".kmz", ".3mf", ".xps", ".oxps", ".cbz", ".usdz",
})
OLE_FAMILY: FrozenSet[str] = frozenset({
    ".doc", ".xls", ".ppt", ".msg", ".hwp", ".msi",
    ".db",  # Windows 썸네일 캐시 Thumbs.db는 OLE 형식이다.
})

# 리눅스·안드로이드 ELF 실행 파일·라이브러리 계열 확장자. 확장자가 없는 것이 가장 흔하다.
_ELF_EXTS: FrozenSet[str] = frozenset({".so", ".elf", ".bin", ".o", ".ko", ".axf", ".prx", ".out", ".mod", ".oat", ".odex"})

# 윈도우 PE(MZ로 시작하는 실행 파일) 계열 확장자.
_PE_EXTS: FrozenSet[str] = frozenset({".exe", ".dll", ".sys", ".scr", ".ocx", ".cpl", ".com", ".efi", ".mui", ".drv"})

# MIME별로 추가로 허용하는 확장자(같은 컨테이너 형식을 공유하는 경우).
EXTRA_ALLOWED_EXTS: Dict[str, FrozenSet[str]] = {
    "text/plain": TEXT_FAMILY,
    # 일반 ZIP에는 내부 구조 확인이 필요한 확장자(.apk·.docx 등)를 허용하지 않는다.
    "application/zip": ZIP_FAMILY - container.STRUCTURE_CHECKED_EXTS,
    "application/vnd.sqlite3": frozenset({".sqlite", ".sqlite3", ".db"}),
    "application/x-sqlite3": frozenset({".sqlite", ".sqlite3", ".db"}),
    "application/x-ole-storage": OLE_FAMILY,
    "application/cdfv2": OLE_FAMILY,
    "application/vnd.ms-office": OLE_FAMILY,
    "application/x-hwp": frozenset({".hwp"}),
    "application/vnd.hancom.hwp": frozenset({".hwp"}),
    "application/haansofthwp": frozenset({".hwp"}),
    "application/vnd.hancom.hwpx": frozenset({".hwpx"}),
    "application/x-bplist": frozenset({".plist"}),
    "image/jpeg": frozenset({".jpg"}),
    # ZIP 내부 구조로 확인한 형식. 모두 ZIP이 맞으므로 .zip도 거짓 확장자가 아니다.
    **{t.mime: t.exts | {".zip"} for t in container.CONTAINER_TYPES.values()},
    # libmagic이 내놓지만 Python 내장 MIME 표에는 확장자가 없는 형식들
    "application/java-archive": frozenset({".jar", ".apk", ".aar"}),
    "application/x-dosexec": _PE_EXTS,
    "application/vnd.microsoft.portable-executable": _PE_EXTS,
    "application/x-7z-compressed": frozenset({".7z"}),
    "application/vnd.rar": frozenset({".rar"}),
    "application/x-rar": frozenset({".rar"}),
    "application/x-executable": _ELF_EXTS,
    "application/x-sharedlib": _ELF_EXTS,
    "application/x-pie-executable": _ELF_EXTS,
    "application/x-object": _ELF_EXTS,
    "application/x-coredump": _ELF_EXTS | {".core"},
    "application/gzip": frozenset({".gz", ".tgz", ".gzip", ".svgz"}),
    "application/x-gzip": frozenset({".gz", ".tgz", ".gzip", ".svgz"}),
    "image/tiff": TIFF_FAMILY,
    "audio/mpeg": frozenset({".mp3"}),
    **{m: ISO_BMFF_FAMILY for m in (
        "video/mp4", "video/quicktime", "audio/mp4", "audio/x-m4a", "video/x-m4v", "video/3gpp", "video/3gpp2",
        "image/heic", "image/heif", "image/avif", "image/x-canon-cr3",
    )},
}

# 허용 확장자를 판단할 수 있는(= 이 도구가 아는) 확장자 전체. 여기에 없는 확장자는
# 불일치 여부를 판정할 근거가 없으므로 "판정 불가"로 두고 불일치로 보지 않는다.
# 예: libc.so.6의 ".6", 커널 모듈 ".ko"(ELF 허용 목록에 있음), 임의의 ".dat"
KNOWN_EXTS: FrozenSet[str] = frozenset(
    set(TEXT_FAMILY) | set(ZIP_FAMILY) | set(OLE_FAMILY) | set(TIFF_FAMILY) | set(ISO_BMFF_FAMILY)
    | {e for exts in EXTRA_ALLOWED_EXTS.values() for e in exts}
    | {_KNOWN_EXT_NORMALIZE.get(e, e) for e in _MIME_DB.types_map[True]}
)

# 확장자가 없을 때 불일치로 보는 형식: 사진·영상·음성·PDF처럼 보통 확장자가 붙는 사용자
# 데이터. 실행 파일(리눅스는 확장자가 없는 게 정상)·텍스트·DB는 확장자가 없어도 흔하다.
NOEXT_SUSPICIOUS_PREFIXES: Tuple[str, ...] = ("image/", "video/", "audio/", "application/pdf")

# 정상이라면 반드시 알려진 시그니처로 시작하는 확장자.
# .db는 SQLite 외에도 형식이 제각각이라 시그니처를 강제하지 않는다.
SIGNATURE_REQUIRED_EXTS: FrozenSet[str] = frozenset(
    (ZIP_FAMILY | OLE_FAMILY | {".png", ".jpg", ".gif", ".pdf", ".sqlite", ".sqlite3", ".gz",
                                ".exe", ".dll", ".7z", ".rar", ".bmp", ".webp", ".wav", ".tiff", ".flac", ".ogg",
                                ".heic"}) - {".db", ".key"}   # .key는 텍스트 키 파일일 수도 있음
)

EMPTY_MIMES: FrozenSet[str] = frozenset({"inode/x-empty", "application/x-empty"})
UNKNOWN_BINARY_MIMES: FrozenSet[str] = frozenset({"", "application/octet-stream"})

# sig_source 값
SOURCE_LIBMAGIC = "libmagic"
SOURCE_HEADER = "header"
SOURCE_CONTAINER = "container"
SOURCE_TEXT = "text"
SOURCE_UNKNOWN = "unknown"
SOURCE_ERROR = "error"
SOURCE_SYMLINK = "symlink"



def probe_file_type(path: Union[str, Path], *, prefer_magic: bool = True) -> Optional[Dict[str, object]]:
    """파일의 실제 바이트를 읽어 형식을 판별한다.

    Args:
        path: 판별할 파일 경로.
        prefer_magic: True이고 python-magic이 설치되어 있으면 libmagic을 우선 쓴다.

    Returns:
        판별 결과. 파일을 읽을 수 없으면 None(빈 파일과 구분하기 위해서다).

        - ``real_mime`` (str): 판별된 MIME. 모르면 ``application/octet-stream``.
        - ``real_ext`` (str): MIME의 대표 확장자(예: ``.png``). 모르면 빈 문자열.
        - ``description`` (str): 사람이 읽을 수 있는 설명.
        - ``source`` (str): 판별 근거(``container``/``libmagic``/``header``/``text``/``unknown``).
        - ``high_entropy`` (bool): 표본 구간 중 압축·암호화 수준의 엔트로피가 있으면 True.
          정상 ZIP·JPEG도 True이므로 이것만으로 의심 파일이라고 볼 수 없다.
        - ``embedded_binary`` (bool): 앞부분은 텍스트인데 중간·끝 구간에 텍스트가
          아닌 데이터가 있으면 True.
        - ``fallback_mime`` / ``fallback_ext`` (str): 내장 판별(매직 넘버 표·텍스트 판별)
          결과. libmagic이 허용 확장자를 알 수 없는 MIME을 내놓았을 때 판정에 쓴다.

    Example:
        >>> probe_file_type("ForensicTestData/images/mismatch_signature.jpg")["real_mime"]
        'image/png'
    """
    samples = _read_samples(path)
    if samples is None:
        return None
    head, others = samples

    if not head:
        return _result("inode/x-empty", "", "empty", SOURCE_HEADER)

    header = _probe_bytes(head)
    result: Optional[Dict[str, object]] = None
    if header["real_mime"] == "application/zip":
        result = _probe_zip(path)
    elif prefer_magic and _HAS_MAGIC:
        try:
            mime = (magic.from_file(str(path), mime=True) or "").lower()
            desc = magic.from_file(str(path), mime=False) or ""
            if mime and mime not in UNKNOWN_BINARY_MIMES:
                result = _result(mime, _ext_from_mime(mime), desc, SOURCE_LIBMAGIC)
        except Exception:
            result = None  # libmagic 오류 시 내장 판별로 넘어간다.
    if result is None:
        result = header
    # libmagic이 우리 표에 없는 MIME을 내놓으면 허용 확장자를 알 수 없다. 그때 판정에
    # 쓸 수 있도록 내장 판별 결과를 함께 넘긴다.
    result["fallback_mime"] = header["real_mime"]
    result["fallback_ext"] = header["real_ext"]

    result["high_entropy"] = any(textutil.is_high_entropy(b) for b in (head, *others))
    if str(result["real_mime"]).startswith("text/"):
        result["embedded_binary"] = any(
            b.rstrip(b"\x00") and textutil.detect_text_encoding(b, partial=True) is None for b in others
        )
    return result


def add_signature_to_rows(
    rows: List[Dict[str, object]],
    *,
    prefer_magic: bool = True,
    follow_symlinks: bool = False,
    disk_ext_field: str = "ext_on_disk",
    sig_prefix: str = "sig_",
) -> List[Dict[str, object]]:
    """인벤토리 행마다 시그니처 판별 결과와 확장자 불일치 여부를 추가한다.

    Args:
        rows: ``collect_inventory`` 결과. ``path``, ``is_symlink`` 열을 사용한다.
        prefer_magic: libmagic 우선 사용 여부.
        follow_symlinks: 인벤토리를 만들 때와 같은 값을 줘야 한다. False이면
            심볼릭 링크는 판별하지 않는다(``sig_source=symlink``).
        disk_ext_field: 디스크상 확장자를 기록할 열 이름.
        sig_prefix: 추가할 시그니처 열의 접두어.

    Returns:
        입력 ``rows``를 제자리에서 수정해 그대로 반환한다. 추가 열은 다음과 같다.

        - ``{sig_prefix}mime`` / ``ext`` / ``desc``: 판별된 MIME, 대표 확장자, 설명
        - ``{sig_prefix}source``: 판별 근거. 읽기 실패는 ``error``, 링크는 ``symlink``
        - ``{sig_prefix}high_entropy``: 압축·암호화 수준 엔트로피 구간이 있음
          (정상 ZIP·JPEG도 True)
        - ``{disk_ext_field}``: 디스크상 확장자
        - ``ext_mismatch``: 확장자와 실제 내용이 어긋나면 True
    """
    for row in rows:
        p = row.get("path")
        disk_ext = _disk_extension(str(p)) if p else ""
        row[disk_ext_field] = disk_ext

        if row.get("is_symlink") and not follow_symlinks:
            _fill_blank(row, sig_prefix, SOURCE_SYMLINK, "심볼릭 링크(따라가지 않음)")
            continue
        result = probe_file_type(p, prefer_magic=prefer_magic) if p else None
        if result is None:
            _fill_blank(row, sig_prefix, SOURCE_ERROR, "파일을 읽을 수 없음")
            continue

        row[f"{sig_prefix}mime"] = result["real_mime"]
        row[f"{sig_prefix}ext"] = result["real_ext"]
        row[f"{sig_prefix}desc"] = result["description"]
        row[f"{sig_prefix}source"] = result["source"]
        row[f"{sig_prefix}high_entropy"] = bool(result["high_entropy"])
        row["ext_mismatch"] = is_ext_mismatch(
            disk_ext,
            str(result["real_mime"]),
            str(result["real_ext"]),
            embedded_binary=bool(result.get("embedded_binary")),
            fallback_mime=str(result.get("fallback_mime") or ""),
            fallback_ext=str(result.get("fallback_ext") or ""),
        )
        if result.get("embedded_binary"):
            row[f"{sig_prefix}desc"] = f"{result['description']} / 중간·끝 구간에 텍스트가 아닌 데이터"
    return rows


def is_ext_mismatch(
    disk_ext: str,
    real_mime: str,
    real_ext: str,
    *,
    embedded_binary: bool = False,
    fallback_mime: str = "",
    fallback_ext: str = "",
) -> bool:
    """디스크상 확장자가 실제 내용과 어긋나는지 판정한다.

    판정 규칙:
        - 빈 파일이면 False(내용이 없으니 어떤 확장자와도 모순되지 않는다).
        - 실제 내용이 "알 수 없는 바이너리"일 때:
            * .png·.pdf·.zip·.hwp처럼 시그니처가 있어야 하는 확장자면 True(헤더 훼손·위장).
            * .txt·.log 같은 텍스트 확장자면 True. 지원하는 어떤 인코딩으로도 텍스트가
              아니라는 뜻이다(암호화·바이너리 은닉).
            * .bin·.dat처럼 원래 아무 바이너리나 담는 확장자면 False.
        - 텍스트로 판정됐어도 텍스트 확장자인데 중간·끝 구간에 텍스트가 아닌 데이터가
          있으면 True(텍스트 뒤에 데이터 은닉).
        - 확장자가 없으면, 사진·영상·음성·PDF일 때만 True(확장자를 떼어 숨긴 경우).
          리눅스 실행 파일·텍스트·DB처럼 원래 확장자 없이 흔한 형식은 False.
        - 이 도구가 모르는 확장자(``KNOWN_EXTS``에 없음, 예: ``libc.so.6``의 ``.6``)면
          판정할 근거가 없으므로 False("판정 불가").
        - ZIP은 내부 구조로 판별한 형식을 기준으로 본다. ``.apk``·``.ipa``·``.docx``·
          ``.hwpx``처럼 내부 구조가 정해진 확장자인데 그 구조가 아니면 True(일반 ZIP을
          ``.apk``로, APK를 ``.docx``로 바꾼 경우). APK·DOCX 등을 ``.zip``으로 둔 것은
          False(ZIP인 것은 사실이다).
        - 그 밖에는 허용 확장자 집합에 없으면 True. libmagic이 우리 표에 없는 MIME을
          내놓아 허용 집합이 비면, 내장 판별 결과(``fallback_*``)의 허용 집합을 쓴다.
          그래도 비면 판정할 수 없으므로 False.

    Args:
        disk_ext: 디스크상 확장자.
        real_mime: 판별된 MIME.
        real_ext: 판별된 대표 확장자.
        embedded_binary: 텍스트 파일의 중간·끝 구간에 텍스트가 아닌 데이터가 있는지.
        fallback_mime: 내장 판별 MIME(libmagic 결과를 해석할 수 없을 때 사용).
        fallback_ext: 내장 판별 대표 확장자.

    Returns:
        불일치이면 True.

    Example:
        >>> is_ext_mismatch(".jpg", "image/png", ".png")
        True
        >>> is_ext_mismatch(".txt", "application/octet-stream", "")
        True
        >>> is_ext_mismatch(".bin", "application/octet-stream", "")
        False
        >>> is_ext_mismatch(".hwp", "application/x-ole-storage", ".doc")
        False
        >>> is_ext_mismatch(".jpg", "application/x-dosexec", ".exe")   # 사진으로 위장한 실행 파일
        True
        >>> is_ext_mismatch("", "application/x-executable", "")        # 확장자 없는 리눅스 실행 파일
        False
        >>> is_ext_mismatch(".cr2", "image/tiff", ".tiff")             # TIFF 구조의 카메라 RAW
        False
        >>> is_ext_mismatch(".apk", "application/zip", ".zip")         # 앱 구조가 없는 일반 ZIP
        True
        >>> is_ext_mismatch(".zip", "application/vnd.android.package-archive", ".apk")
        False
    """
    mime = (real_mime or "").lower()
    d = _normalize_ext(disk_ext)

    if mime in EMPTY_MIMES:
        return False
    if not d:
        return mime.startswith(NOEXT_SUSPICIOUS_PREFIXES)
    if d not in KNOWN_EXTS:
        return False
    if mime in UNKNOWN_BINARY_MIMES:
        return d in SIGNATURE_REQUIRED_EXTS or d in TEXT_FAMILY
    if mime.startswith("text/") and embedded_binary and d in TEXT_FAMILY:
        return True

    allowed = _allowed_exts(mime, real_ext)
    if not allowed and fallback_mime and fallback_mime.lower() not in UNKNOWN_BINARY_MIMES | EMPTY_MIMES:
        allowed = _allowed_exts(fallback_mime.lower(), fallback_ext)
    if not allowed:
        return False
    return d not in allowed


# ---------------------------------------------------------------------------
# 내부 유틸
# ---------------------------------------------------------------------------

def _result(mime: str, ext: str, desc: str, source: str) -> Dict[str, object]:
    """판별 결과 딕셔너리를 기본값과 함께 만든다.

    Args:
        mime: MIME.
        ext: 대표 확장자.
        desc: 설명.
        source: 판별 근거.

    Returns:
        ``probe_file_type`` 반환 형식의 딕셔너리.
    """
    return {"real_mime": mime, "real_ext": ext, "description": desc, "source": source,
            "high_entropy": False, "embedded_binary": False,
            "fallback_mime": "", "fallback_ext": ""}


def _probe_zip(path: Union[str, Path]) -> Dict[str, object]:
    """ZIP 내부 구조로 형식을 판별한다.

    Args:
        path: ``PK``로 시작하는 파일 경로.

    Returns:
        ``_result`` 형식의 딕셔너리. 앱·문서 구조가 확인되지 않으면(손상된 ZIP 포함)
        ``application/zip``이다.
    """
    found = container.inspect_zip(path)
    if found.kind:
        t = container.CONTAINER_TYPES[found.kind]
        return _result(t.mime, t.ext, found.desc, SOURCE_CONTAINER)
    return _result("application/zip", ".zip", found.desc, SOURCE_CONTAINER)


def _probe_bytes(head: bytes) -> Dict[str, object]:
    """libmagic 없이 앞부분 바이트만으로 형식을 판별한다.

    Args:
        head: 파일 앞부분 바이트(비어 있지 않음).

    Returns:
        ``_result`` 형식의 딕셔너리.
    """
    if head[:4] == b"RIFF" and head[8:12] in RIFF_FORMS:
        mime, ext = RIFF_FORMS[head[8:12]]
        return _result(mime, ext, f"매직 넘버 일치(RIFF {head[8:12]!r})", SOURCE_HEADER)
    if head[4:8] == b"ftyp":
        mime, ext = FTYP_BRANDS.get(head[8:12], ("video/mp4", ".mp4"))
        return _result(mime, ext, f"매직 넘버 일치(ftyp {head[8:12]!r})", SOURCE_HEADER)
    for offset, sig, mime, ext in SIGNATURES:
        if head[offset:offset + len(sig)] == sig:
            return _result(mime, ext, f"매직 넘버 일치({sig[:8]!r})", SOURCE_HEADER)
    if _is_pe(head):
        return _result("application/x-dosexec", ".exe", "윈도우 실행 파일(MZ + PE 헤더)", SOURCE_HEADER)
    if head[:2] == b"BM" and len(head) >= 18 and int.from_bytes(head[14:18], "little") in _BMP_DIB_SIZES:
        return _result("image/bmp", ".bmp", "매직 넘버 일치(BM + DIB 헤더)", SOURCE_HEADER)
    enc = textutil.detect_text_encoding(head)
    if enc:
        return _result("text/plain", ".txt", f"텍스트({enc})", SOURCE_TEXT)
    if not head.rstrip(b"\x00"):
        return _result("application/octet-stream", "", "NUL 바이트로만 채워짐", SOURCE_UNKNOWN)
    return _result("application/octet-stream", "", "알 수 없는 바이너리", SOURCE_UNKNOWN)


def _is_pe(head: bytes) -> bool:
    """윈도우 PE 실행 파일인지 확인한다.

    ``MZ``로 시작하고, 0x3C 위치의 4바이트 값(PE 헤더 위치)이 가리키는 곳에
    ``PE\\0\\0``이 있어야 한다. EXE·DLL·SYS가 모두 이 구조다.

    Args:
        head: 파일 앞부분 바이트.

    Returns:
        PE 구조이면 True.

    Example:
        >>> _is_pe(b"MZ is a city in text")
        False
    """
    if head[:2] != b"MZ" or len(head) < 0x40:
        return False
    pe_offset = int.from_bytes(head[0x3C:0x40], "little")
    return 0x40 <= pe_offset <= len(head) - 4 and head[pe_offset:pe_offset + 4] == b"PE\x00\x00"


def _read_samples(path: Union[str, Path]) -> Optional[Tuple[bytes, Tuple[bytes, ...]]]:
    """파일의 앞부분과, 파일이 크면 중간·끝 구간 표본을 읽는다.

    Args:
        path: 파일 경로.

    Returns:
        ``(앞부분, (중간, 끝))``. 파일이 ``SAMPLE_BYTES``의 두 배 이하면 중간·끝은
        생략한다(앞부분과 겹치므로). 읽기에 실패하면 None.
    """
    try:
        with Path(path).open("rb") as f:
            head = f.read(SAMPLE_BYTES)
            f.seek(0, 2)
            size = f.tell()
            others: List[bytes] = []
            if size > SAMPLE_BYTES * 2:
                for start in ((size - SAMPLE_BYTES) // 2, size - SAMPLE_BYTES):
                    f.seek(start)
                    others.append(f.read(SAMPLE_BYTES))
            return head, tuple(others)
    except OSError:
        return None


def _fill_blank(row: Dict[str, object], sig_prefix: str, source: str, desc: str) -> None:
    """판별하지 않은(또는 못 한) 행의 시그니처 열을 채운다.

    Args:
        row: 인벤토리 행.
        sig_prefix: 시그니처 열 접두어.
        source: ``sig_source`` 값.
        desc: ``sig_desc`` 값.
    """
    row[f"{sig_prefix}mime"] = ""
    row[f"{sig_prefix}ext"] = ""
    row[f"{sig_prefix}desc"] = desc
    row[f"{sig_prefix}source"] = source
    row[f"{sig_prefix}high_entropy"] = ""
    row["ext_mismatch"] = False


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
        정규화된 확장자. 없으면 빈 문자열.
    """
    return _normalize_ext(Path(path).suffix)


def _ext_from_mime(mime: str) -> str:
    """MIME에서 대표 확장자를 추정한다(OS 설정과 무관한 내장 표 사용).

    Args:
        mime: MIME 문자열.

    Returns:
        정규화된 대표 확장자. 모르면 빈 문자열.
    """
    return _normalize_ext(_MIME_DB.guess_extension(mime) or "") if mime else ""


def _allowed_exts(mime: str, real_ext: str) -> FrozenSet[str]:
    """해당 MIME으로 판별된 파일이 가져도 정상인 확장자 집합을 만든다.

    Args:
        mime: 판별된 MIME(소문자).
        real_ext: 판별된 대표 확장자.

    Returns:
        허용 확장자 집합. 비어 있으면 판정 불가를 뜻한다.
    """
    allowed = {_normalize_ext(e) for e in _MIME_DB.guess_all_extensions(mime)}
    if real_ext:
        allowed.add(_normalize_ext(real_ext))
    allowed |= EXTRA_ALLOWED_EXTS.get(mime, frozenset())
    if mime.startswith("text/"):
        allowed |= TEXT_FAMILY  # text/csv, text/x-script.python 등 세부 판별 차이를 흡수
    allowed.discard("")
    return frozenset(allowed)
