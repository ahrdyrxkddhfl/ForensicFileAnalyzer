# forensic_analyzer/container.py
"""ZIP 내부 구조로 실제 형식(앱 패키지·문서)을 판별한다.

APK·IPA·DOCX·HWPX는 모두 ZIP이라 앞부분 시그니처(``PK\\x03\\x04``)만으로는 구분할 수
없다. 그래서 ZIP 안을 열어 형식마다 반드시 있어야 하는 파일이 있는지 확인한다.
"확장자를 믿지 않는다"는 원칙을 컨테이너 안쪽까지 넓힌 것이다.

내부 파일도 이름만으로는 믿지 않는다. 앱 패키지는 핵심 파일의 앞부분 바이트까지 본다.

- APK: ``AndroidManifest.xml``이 빌드 때 컴파일된 바이너리 XML(``03 00 08 00``)이어야
  한다. ``classes*.dex``가 있으면 DEX 시그니처(``dex\\n``)로 시작해야 한다. DEX가 없는
  APK(리소스 전용·분할 APK)도 있으므로 DEX는 필수로 보지 않는다.
- IPA: ``Payload/<앱 이름>.app/Info.plist``가 있고, 그 내용이 plist(바이너리 또는 XML)여야 한다.
- DOCX·XLSX·PPTX: ``[Content_Types].xml``과 본문 폴더(``word/``·``xl/``·``ppt/``)가 있어야 한다.
- HWPX·ODT·ODS·ODP·EPUB: 내부 파일 ``mimetype``에 적힌 형식 이름으로 가른다.

판정할 수 없는 경우는 "아니다"와 구분해 기록한다. 같은 이름의 내부 파일이 여러 개이거나,
핵심 파일을 읽을 수 없으면(암호화 플래그·지원하지 않는 압축 방식) 어느 형식으로도 인정하지
않는다. 안드로이드는 이런 조작을 무시하고 설치하지만 분석 도구는 막히므로, 악성 앱이 분석을
방해하려고 쓸 수 있다.

Example:
    >>> import io, zipfile
    >>> buf = io.BytesIO()
    >>> with zipfile.ZipFile(buf, "w") as zf:
    ...     zf.writestr("AndroidManifest.xml", b"<manifest/>")
    >>> inspect_zip(buf).kind      # 이름만 맞춘 텍스트 매니페스트는 APK가 아니다
    ''
"""
from __future__ import annotations

import re
import zipfile
from collections import Counter
from pathlib import Path
from typing import BinaryIO, Dict, FrozenSet, NamedTuple, Optional, Set, Union


class ContainerType(NamedTuple):
    """ZIP 기반 형식 하나의 정보."""

    mime: str
    ext: str                 # 대표 확장자
    label: str               # 결과에 표시할 이름
    exts: FrozenSet[str]     # 이 형식이 가져도 정상인 확장자


class ZipInspection(NamedTuple):
    """ZIP 내부 구조 판별 결과."""

    kind: str   # ``CONTAINER_TYPES``의 키. 어느 형식도 아니거나 읽지 못하면 빈 문자열
    desc: str   # 판정 근거 설명


CONTAINER_TYPES: Dict[str, ContainerType] = {
    "apk": ContainerType("application/vnd.android.package-archive", ".apk", "안드로이드 앱(APK)",
                         frozenset({".apk"})),
    "ipa": ContainerType("application/x-ios-app", ".ipa", "iOS 앱(IPA)", frozenset({".ipa"})),
    "docx": ContainerType("application/vnd.openxmlformats-officedocument.wordprocessingml.document", ".docx",
                          "Word 문서", frozenset({".docx", ".docm"})),
    "xlsx": ContainerType("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", ".xlsx",
                          "Excel 문서", frozenset({".xlsx", ".xlsm"})),
    "pptx": ContainerType("application/vnd.openxmlformats-officedocument.presentationml.presentation", ".pptx",
                          "PowerPoint 문서", frozenset({".pptx", ".pptm"})),
    "hwpx": ContainerType("application/hwp+zip", ".hwpx", "한글 문서(HWPX)", frozenset({".hwpx"})),
    "odt": ContainerType("application/vnd.oasis.opendocument.text", ".odt", "OpenDocument 텍스트",
                         frozenset({".odt"})),
    "ods": ContainerType("application/vnd.oasis.opendocument.spreadsheet", ".ods", "OpenDocument 스프레드시트",
                         frozenset({".ods"})),
    "odp": ContainerType("application/vnd.oasis.opendocument.presentation", ".odp", "OpenDocument 프레젠테이션",
                         frozenset({".odp"})),
    "epub": ContainerType("application/epub+zip", ".epub", "전자책(EPUB)", frozenset({".epub"})),
}

# 이 확장자를 단 ZIP은 내부 구조가 확인되어야 정상이다. 일반 ZIP을 ``.apk``로 바꾼 파일을 잡는다.
STRUCTURE_CHECKED_EXTS: FrozenSet[str] = frozenset(e for t in CONTAINER_TYPES.values() for e in t.exts)

# 컴파일된 바이너리 XML 헤더: 청크 종류 0x0003(RES_XML_TYPE), 헤더 크기 0x0008(리틀 엔디언).
AXML_MAGIC = b"\x03\x00\x08\x00"
DEX_MAGIC = b"dex\n"

_DEX_NAME = re.compile(r"classes\d*\.dex")
_IPA_PLIST = re.compile(r"Payload/[^/]+\.app/Info\.plist")
_OOXML_PARTS = (("word/", "docx"), ("xl/", "xlsx"), ("ppt/", "pptx"))
_MIMETYPE_KINDS: Dict[str, str] = {CONTAINER_TYPES[k].mime: k for k in ("hwpx", "odt", "ods", "odp", "epub")}


def inspect_zip(source: Union[str, Path, BinaryIO]) -> ZipInspection:
    """ZIP을 열어 내부 구조로 앱 패키지·문서 형식을 판별한다.

    확장자는 보지 않는다. 확장자와 비교하는 일은 ``signature.is_ext_mismatch``가 한다.

    Args:
        source: ZIP 파일 경로 또는 바이너리 파일 객체.

    Returns:
        판별 결과. 어느 형식도 아니면 ``kind``가 빈 문자열이다. ZIP 구조를 읽지
        못하면(끝이 잘림·손상) 마찬가지로 빈 문자열이고 ``desc``에 이유를 남긴다.
    """
    try:
        with zipfile.ZipFile(source) as zf:
            names = zf.namelist()
            dup = sorted(n for n, c in Counter(names).items() if c > 1)
            if dup:  # zipfile은 같은 이름 중 마지막 것만 읽으므로 무엇을 판정했는지 보장할 수 없다.
                return ZipInspection("", f"같은 이름의 내부 파일이 여러 개: {dup[0]}(변조 의심)")
            return _identify(zf, set(names))
    except Exception as e:  # 증거 파일은 일부러 망가뜨린 것일 수 있어 zipfile이 여러 예외를 낸다.
        return ZipInspection("", f"ZIP 구조를 읽을 수 없음({type(e).__name__})")


def _identify(zf: zipfile.ZipFile, names: Set[str]) -> ZipInspection:
    """내부 파일 목록과 핵심 파일 내용으로 형식을 고른다.

    Args:
        zf: 열린 ZIP.
        names: 내부 파일 이름 집합.

    Returns:
        판별 결과.
    """
    if "AndroidManifest.xml" in names:
        return _check_apk(zf, names)
    plists = sorted(n for n in names if _IPA_PLIST.fullmatch(n))
    if plists:
        return _check_ipa(zf, plists[0])
    if "[Content_Types].xml" in names:
        for prefix, kind in _OOXML_PARTS:
            if any(n.startswith(prefix) for n in names):
                return ZipInspection(kind, f"{CONTAINER_TYPES[kind].label}: [Content_Types].xml, {prefix} 폴더")
    if "mimetype" in names:
        declared = (_read_head(zf, "mimetype", 100) or b"").strip().decode("ascii", "replace")
        kind = _MIMETYPE_KINDS.get(declared, "")
        if kind:
            return ZipInspection(kind, f"{CONTAINER_TYPES[kind].label}: mimetype={declared}")
        if declared:
            return ZipInspection("", f"일반 ZIP(내부 구조로 확인하는 형식 아님, mimetype={declared})")
    return ZipInspection("", "일반 ZIP(내부 구조로 확인하는 형식 아님)")


def _check_apk(zf: zipfile.ZipFile, names: Set[str]) -> ZipInspection:
    """``AndroidManifest.xml``이 있는 ZIP이 실제 APK인지 확인한다.

    Args:
        zf: 열린 ZIP.
        names: 내부 파일 이름 집합.

    Returns:
        판별 결과.
    """
    manifest = _read_head(zf, "AndroidManifest.xml", 4)
    if manifest is None:
        return _unreadable("AndroidManifest.xml")
    if manifest != AXML_MAGIC:
        return ZipInspection("", "AndroidManifest.xml: 컴파일된 바이너리 XML이 아님(APK 아님)")
    dex = sorted(n for n in names if _DEX_NAME.fullmatch(n))
    for n in dex:
        head = _read_head(zf, n, 4)
        if head is None:
            return _unreadable(n)
        if head != DEX_MAGIC:
            return ZipInspection("", f"{n}: DEX 시그니처로 시작하지 않음(APK 아님)")
    detail = f"DEX {len(dex)}개" if dex else "DEX 없음(리소스 전용·분할 APK일 수 있음)"
    return ZipInspection("apk", f"{CONTAINER_TYPES['apk'].label}: 바이너리 AndroidManifest.xml, {detail}")


def _check_ipa(zf: zipfile.ZipFile, plist_name: str) -> ZipInspection:
    """``Payload/<앱>.app/Info.plist``가 있는 ZIP이 실제 IPA인지 확인한다.

    Args:
        zf: 열린 ZIP.
        plist_name: ``Info.plist``의 내부 경로.

    Returns:
        판별 결과.
    """
    head = _read_head(zf, plist_name, 64)
    if head is None:
        return _unreadable(plist_name)
    if not head.lstrip(b"\xef\xbb\xbf \t\r\n").startswith((b"bplist00", b"<?xml", b"<plist")):
        return ZipInspection("", f"{plist_name}: plist 형식이 아님(IPA 아님)")
    app = plist_name.split("/")[1]
    return ZipInspection("ipa", f"{CONTAINER_TYPES['ipa'].label}: {app}")


def _unreadable(name: str) -> ZipInspection:
    """핵심 내부 파일을 읽지 못한 결과를 만든다. 형식이 아니라고 단정하지 않는다.

    Args:
        name: 읽지 못한 내부 파일 이름.

    Returns:
        ``kind``가 빈 문자열인 판별 결과.
    """
    return ZipInspection("", f"{name}: 읽을 수 없음(암호화 플래그·지원하지 않는 압축 방식 등, 분석 방해 기법일 수 있음)")


def _read_head(zf: zipfile.ZipFile, name: str, size: int) -> Optional[bytes]:
    """내부 파일의 앞부분만 읽는다(압축을 전부 풀지 않는다).

    Args:
        zf: 열린 ZIP.
        name: 내부 파일 이름.
        size: 읽을 바이트 수.

    Returns:
        앞부분 바이트. 암호화·손상·지원하지 않는 압축 방식이면 None.
    """
    try:
        with zf.open(name) as f:
            return f.read(size)
    except Exception:
        return None

