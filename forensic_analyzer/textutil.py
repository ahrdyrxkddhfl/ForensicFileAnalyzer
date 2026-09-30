# forensic_analyzer/textutil.py
"""바이트열이 "사람이 읽는 텍스트"인지 판별하는 공용 유틸리티.

시그니처 판별(signature.py)과 키워드 검색(search.py)이 같은 기준을 쓰도록
텍스트 판별 로직을 한곳에 모았다.

판별 원칙:
    인코딩별로 **실제 디코딩이 되는지**와, 디코딩 결과 중 **출력 가능한 문자의
    비율**이 충분히 높은지를 함께 본다. 디코딩만 보면 latin-1처럼 모든 바이트를
    받아들이는 인코딩이나, 우연히 디코딩되는 무작위 바이트를 걸러낼 수 없기 때문이다.

    예를 들어 무작위 바이트를 CP1252로 디코딩하면 성공할 때도 있지만, 제어 문자가
    섞여 출력 가능 비율이 90%에 못 미친다. 반면 사람이 쓴 문서는 거의 100%다.

Example:
    >>> detect_text_encoding("비밀번호 변경".encode("cp949"))
    'cp949'
    >>> detect_text_encoding(bytes(range(256)) * 16) is None
    True
"""
from __future__ import annotations

import math
import re
from collections import Counter
from typing import Iterable, Optional, Tuple

# 텍스트로 인정할 최소 출력 가능 문자 비율.
MIN_PRINTABLE_RATIO = 0.9

# 거의 모든 바이트를 받아들이는 인코딩은 무작위 바이트도 디코딩에 성공하기 쉬우므로
# 더 엄격한 비율을 요구한다. 사람이 쓴 서유럽 문서는 출력 가능 비율이 사실상 100%다.
STRICT_PRINTABLE_RATIO: dict = {"cp1252": 0.97}

# 레거시(단일/멀티 바이트) 인코딩으로 판별할 때 허용하는 NUL 바이트 비율 상한.
# UTF-8·CP949 문서에는 NUL이 거의 없다. NUL이 많으면 UTF-16이거나 바이너리다.
MAX_LEGACY_NUL_RATIO = 0.01

# 이 길이 이상 이어진 NUL 구간은 레거시 판별 전에 떼어 놓는다. 미리 할당된 로그나
# 크래시로 중간이 0으로 채워진 로그에 흔하다. UTF-16 텍스트의 NUL은 글자 사이에 한두
# 개씩 흩어져 있으므로 이 처리에 영향을 받지 않는다.
_NUL_RUN = re.compile(rb"\x00{8,}")

# 기본으로 시도하는 레거시 인코딩. 한국 수사 환경을 우선하고 일본어·중국어·서유럽을 보조로 둔다.
# cp1252는 거의 모든 바이트를 받아들이므로 반드시 마지막에 둔다.
DEFAULT_LEGACY_ENCODINGS: Tuple[str, ...] = ("utf-8", "cp949", "shift_jis", "gbk", "cp1252")

# BOM 없는 UTF-16 판별 기준. 아래 "detect_utf16_without_bom" 참고.
UTF16_NUL_PARITY_MIN = 0.05   # 이 비율 이상 NUL이 한쪽 자리에 있으면 "ASCII가 섞인 UTF-16" 후보
UTF16_PLAUSIBLE_MIN_RATIO = 0.9  # ASCII가 섞인 UTF-16: 그럴듯한 글자 비율 하한
UTF16_CJK_MIN_RATIO = 0.9     # ASCII가 거의 없는 UTF-16: 한중일 문자 비율 하한
UTF16_MIN_JUDGE_BYTES = 16     # 이보다 짧은 UTF-16 본문은 분포로 판단할 수 없다(8글자)
# ASCII 소문자 두 글자(예: "pl" = 0x706C)를 UTF-16으로 읽으면 한자 범위에 들어간다.
# 그래서 바이트 대부분이 출력 가능한 ASCII면 "ASCII가 거의 없는 한중일 UTF-16"으로 보지 않는다.
# 실제 한중일 UTF-16은 한 바이트가 0x80 이상인 경우가 많아 이 비율이 대략 0.5~0.75다.
UTF16_CJK_MAX_ASCII_RATIO = 0.9

# BOM → 인코딩. UTF-32 LE BOM(FF FE 00 00)은 UTF-16 LE BOM(FF FE)을 포함하므로 먼저 둔다.
BOM_ENCODINGS: Tuple[Tuple[bytes, str], ...] = (
    (b"\xff\xfe\x00\x00", "utf-32"),
    (b"\x00\x00\xfe\xff", "utf-32"),
    (b"\xef\xbb\xbf", "utf-8-sig"),
    (b"\xff\xfe", "utf-16"),
    (b"\xfe\xff", "utf-16"),
)

# 이보다 작은 표본은 무작위 바이트가 우연히 텍스트 조건을 통과할 확률이 무시할 수 없다.
# 실측값은 tests/test_textutil.py의 오판률 테스트로 확인한다.
RELIABLE_TEXT_MIN_BYTES = 256

# 엔트로피가 이 값(바이트당 비트, 최대 8) 이상이면 압축·암호화 수준으로 본다.
HIGH_ENTROPY_BITS = 7.0
# 표본이 작으면 엔트로피가 낮게 나와 판단할 수 없으므로 최소 크기를 둔다.
ENTROPY_MIN_BYTES = 256

# 텍스트에 정상적으로 들어가는 제어 문자. ESC(\x1b)는 색상 코드가 들어간 터미널 로그에 흔하다.
_ALLOWED_CONTROL_CHARS = frozenset("\t\n\r\f\v\x1b")

# 출력 가능한 ASCII와 탭·줄바꿈 바이트(빠른 계산용 삭제 표).
_ASCII_TEXT_BYTES = bytes(range(0x20, 0x7F)) + b"\t\n\r"

# 한중일 문자 범위(한글 음절, 한중일 통합 한자, 가나, 한중일 문장부호, 전각 문자).
_CJK_RANGES: Tuple[Tuple[int, int], ...] = (
    (0xAC00, 0xD7A3), (0x4E00, 0x9FFF), (0x3040, 0x30FF), (0x3000, 0x303F), (0xFF00, 0xFFEF),
)


def printable_ratio(text: str) -> float:
    """문자열에서 출력 가능한 문자의 비율을 계산한다.

    탭·줄바꿈 같은 공백 제어 문자는 출력 가능으로 센다. 한글·한자·가나는
    ``str.isprintable()``이 True이므로 그대로 출력 가능으로 센다.

    Args:
        text: 검사할 문자열.

    Returns:
        0.0~1.0 사이의 비율. 빈 문자열이면 1.0.

    Example:
        >>> printable_ratio("abc\\x00")
        0.75
    """
    if not text:
        return 1.0
    ok = sum(1 for ch in text if ch.isprintable() or ch in _ALLOWED_CONTROL_CHARS)
    return ok / len(text)


def _cjk_ratio(text: str) -> float:
    """문자열 중 한중일 문자(한글·한자·가나·전각 등)의 비율을 계산한다.

    Args:
        text: 검사할 문자열.

    Returns:
        0.0~1.0 사이의 비율. 빈 문자열이면 0.0.
    """
    if not text:
        return 0.0
    hit = sum(1 for ch in text if any(lo <= ord(ch) <= hi for lo, hi in _CJK_RANGES))
    return hit / len(text)


def _plausible_ratio(text: str) -> float:
    """사람이 쓴 글에 흔한 글자(ASCII, 라틴 확장, 일반 문장부호, 한중일 문자)의 비율.

    같은 바이트를 두 가지 바이트 순서로 읽었을 때 어느 쪽이 맞는지 고르는 데 쓴다.
    올바른 순서로 읽으면 이 비율이 높고, 반대로 읽으면 흔치 않은 문자 영역이 섞인다.

    Args:
        text: 검사할 문자열.

    Returns:
        0.0~1.0 사이의 비율. 빈 문자열이면 0.0.
    """
    if not text:
        return 0.0
    hit = 0
    for ch in text:
        o = ord(ch)
        if (0x20 <= o <= 0x7E or ch in _ALLOWED_CONTROL_CHARS or 0xA0 <= o <= 0x17F
                or 0x2010 <= o <= 0x205E or any(lo <= o <= hi for lo, hi in _CJK_RANGES)):
            hit += 1
    return hit / len(text)


def _ascii_byte_ratio(buf: bytes) -> float:
    """바이트 중 출력 가능한 ASCII(0x20~0x7E)와 탭·줄바꿈의 비율을 계산한다.

    Args:
        buf: 검사할 바이트열.

    Returns:
        0.0~1.0 사이의 비율. 빈 입력이면 0.0.
    """
    if not buf:
        return 0.0
    return (len(buf) - len(buf.translate(None, _ASCII_TEXT_BYTES))) / len(buf)


def detect_utf16_without_bom(buf: bytes, *, partial: bool = False) -> Optional[str]:
    """BOM 없는 UTF-16 텍스트인지 판별해 ``utf-16-le`` / ``utf-16-be``를 반환한다.

    아무 바이트열이나 UTF-16으로 억지로 읽으면 "출력 가능한 한자"처럼 보이는 경우가
    많아, 디코딩 성공만으로는 판별할 수 없다. 그래서 두 바이트 순서로 모두 읽어 보고,
    아래 조건을 통과한 쪽 중 "그럴듯한 글자" 비율이 가장 높은 쪽을 고른다.

    1. ASCII(공백·줄바꿈·숫자 포함)가 섞인 UTF-16: 이 문자들은 한 바이트가 0x00이므로
       NUL이 적어도 한쪽 자리에 어느 정도(5% 이상) 나타난다. 이때는 디코딩 결과의
       대부분(90% 이상)이 ASCII·라틴·문장부호·한중일 문자여야 한다.
       예: ``"A한"`` → UTF-16 LE ``41 00 5C D5`` (NUL이 홀수 자리)
    2. ASCII가 거의 없는 UTF-16: 디코딩한 글자의 대부분이 한글·한자·가나이고,
       원본 바이트의 대부분이 ASCII는 아니어야 한다(ASCII 문서를 한자로 오인하지 않도록).

    무작위 바이트는 디코딩한 글자가 유니코드 전 영역에 퍼져 두 조건을 통과하지 못한다.
    한글 음절 중 일부(예: '밀' U+BC00)는 한 바이트가 0x00이라 NUL이 양쪽 자리에 섞이므로,
    "NUL이 한쪽에만 있다" 같은 분포 비율 대신 디코딩 결과로 판단한다.

    Args:
        buf: 검사할 바이트열.
        partial: 파일 중간 구간이라 2바이트 정렬이 어긋났을 수 있으면 True.

    Returns:
        ``utf-16-le`` 또는 ``utf-16-be``. 해당하지 않으면 None.

    Example:
        >>> detect_utf16_without_bom("한국어 메모 비밀번호 ".encode("utf-16-le") * 3)
        'utf-16-le'
        >>> detect_utf16_without_bom(b"plain ascii text") is None
        True
    """
    best: Optional[Tuple[float, str]] = None
    for off in ((0, 1) if partial else (0,)):
        body = buf[off:]
        body = body[: len(body) - (len(body) % 2)]
        if len(body) < UTF16_MIN_JUDGE_BYTES:
            continue
        units = len(body) // 2
        # 바이트 슬라이싱으로 세면 C 수준 속도라 큰 파일에서도 빠르다.
        has_ascii = max(body[0::2].count(0), body[1::2].count(0)) / units >= UTF16_NUL_PARITY_MIN
        cjk_allowed = _ascii_byte_ratio(body) < UTF16_CJK_MAX_ASCII_RATIO

        for enc in ("utf-16-le", "utf-16-be"):
            text = decode_tolerant(body, enc, trim_end=(0, 2))
            if text is None or printable_ratio(text) < MIN_PRINTABLE_RATIO:
                continue
            score = _plausible_ratio(text)
            if has_ascii:
                ok = score >= UTF16_PLAUSIBLE_MIN_RATIO
            else:
                ok = cjk_allowed and _cjk_ratio(text) >= UTF16_CJK_MIN_RATIO
            if ok and (best is None or score > best[0]):
                best = (score, enc)
    return best[1] if best else None


def shannon_entropy(buf: bytes) -> float:
    """바이트열의 섀넌 엔트로피(바이트당 비트, 0~8)를 계산한다.

    값이 8에 가까울수록 바이트가 고르게 분포한다(무작위·암호화·압축 데이터).

    Args:
        buf: 계산할 바이트열.

    Returns:
        엔트로피 값. 빈 입력이면 0.0.

    Example:
        >>> shannon_entropy(b"aaaa")
        0.0
    """
    if not buf:
        return 0.0
    n = len(buf)
    h = -sum(c / n * math.log2(c / n) for c in Counter(buf).values())
    return h if h > 0 else 0.0  # 한 종류 바이트뿐이면 -0.0이 나오므로 0.0으로 통일


def is_high_entropy(buf: bytes) -> bool:
    """표본이 충분히 크고 엔트로피가 압축·암호화 수준인지 확인한다.

    정상적인 ZIP·JPEG 같은 압축 형식도 True가 된다. 이 값 하나만으로 의심 파일이라고
    판단하면 안 되며, 확장자·형식 판별과 함께 해석해야 한다.

    Args:
        buf: 검사할 바이트열.

    Returns:
        ``ENTROPY_MIN_BYTES`` 이상이고 엔트로피가 ``HIGH_ENTROPY_BITS`` 이상이면 True.
    """
    return len(buf) >= ENTROPY_MIN_BYTES and shannon_entropy(buf) >= HIGH_ENTROPY_BITS


def decode_tolerant(
    buf: bytes,
    encoding: str,
    *,
    trim_start: Iterable[int] = (0,),
    trim_end: Iterable[int] = (0, 1, 2, 3),
) -> Optional[str]:
    """버퍼 경계에서 잘린 문자를 허용하며 디코딩을 시도한다.

    파일의 일부만 읽으면 멀티바이트 문자가 앞뒤에서 잘릴 수 있다. 그래서 앞·뒤를
    몇 바이트씩 잘라 가며 엄격 모드(strict)로 디코딩을 시도한다.

    Args:
        buf: 디코딩할 바이트열.
        encoding: 시도할 인코딩 이름.
        trim_start: 앞에서 잘라 볼 바이트 수 후보. 파일 중간 구간을 읽을 때 쓴다.
        trim_end: 뒤에서 잘라 볼 바이트 수 후보.

    Returns:
        디코딩된 문자열. 모든 조합이 실패하면 None.
    """
    for s in trim_start:
        for e in trim_end:
            chunk = buf[s: len(buf) - e if e else None]
            if not chunk:
                continue
            try:
                return chunk.decode(encoding)
            except (UnicodeDecodeError, LookupError):
                continue
    return None


def detect_bom_encoding(buf: bytes) -> Optional[str]:
    """BOM이 있고, BOM이 가리키는 인코딩의 정상 텍스트이면 그 인코딩을 반환한다.

    BOM 몇 바이트만 보고 텍스트로 인정하면, 무작위 바이트 앞에 ``FF FE``만 붙여
    위장 판정을 피할 수 있다. 그래서 실제 디코딩과 출력 가능 비율까지 확인하고,
    UTF-16이면 본문이 ``detect_utf16_without_bom`` 기준(ASCII의 NUL 분포 또는
    한중일 문자 비율)까지 통과해야 인정한다.

    Args:
        buf: 파일 앞부분 바이트.

    Returns:
        ``utf-8-sig`` / ``utf-16`` / ``utf-32`` 중 하나. 해당하지 않으면 None.

    Example:
        >>> detect_bom_encoding("메모".encode("utf-16"))
        'utf-16'
        >>> detect_bom_encoding(b"\\xff\\xfe" + bytes(range(256)) * 16) is None
        True
    """
    for bom, enc in BOM_ENCODINGS:
        if not buf.startswith(bom):
            continue
        text = decode_tolerant(buf, enc)
        if text is None or printable_ratio(text) < MIN_PRINTABLE_RATIO:
            return None
        body = buf[len(bom):]
        if enc == "utf-16" and len(body) >= UTF16_MIN_JUDGE_BYTES:
            # 무작위 바이트도 UTF-16 디코딩에 우연히 성공할 수 있으므로, 판단할 만큼
            # 길면 BOM 뒤 본문이 BOM 없는 UTF-16 기준까지 통과해야 인정한다.
            # 몇 글자짜리 짧은 메모는 그 기준을 적용할 수 없어 디코딩 결과만으로 판단한다.
            if detect_utf16_without_bom(body) is None:
                return None
        return enc
    return None


def detect_text_encoding(
    buf: bytes,
    *,
    legacy_encodings: Iterable[str] = DEFAULT_LEGACY_ENCODINGS,
    partial: bool = False,
) -> Optional[str]:
    """바이트열이 텍스트이면 가장 그럴듯한 인코딩 이름을, 아니면 None을 반환한다.

    판별 순서:
        1. BOM 텍스트(UTF-8/16/32)
        2. NUL이 거의 없으면 레거시 인코딩(UTF-8 → CP949 → Shift-JIS → GBK → CP1252)
        3. BOM 없는 UTF-16 LE/BE (``detect_utf16_without_bom``)
    크래시로 잘린 로그처럼 끝이 NUL로 채워진 파일은 끝의 NUL을 제거하고, 중간에 NUL이
    길게(8바이트 이상) 이어진 구간은 떼어 놓고 판단한다.

    ASCII 문서는 2단계에서 먼저 확정되므로 3단계(UTF-16)로 잘못 가지 않는다.
    ASCII 바이트를 UTF-16으로 억지로 읽으면 출력 가능한 한자처럼 보이기 때문에
    이 순서가 중요하다.

    같은 바이트열이 여러 인코딩으로 동시에 디코딩될 수 있다(예: GBK 중국어 문서가
    CP949로도 디코딩됨). 이 함수의 목적은 "텍스트인가"를 가리는 것이며, 반환한
    인코딩이 원래 인코딩이라고 보장하지는 않는다.

    Args:
        buf: 검사할 바이트열(파일 앞부분 또는 중간 구간).
        legacy_encodings: 2단계에서 시도할 인코딩 목록.
        partial: 파일 중간 구간처럼 앞쪽이 문자 중간에서 잘렸을 수 있으면 True.

    Returns:
        인코딩 이름. 텍스트가 아니면 None. 빈 입력(또는 NUL만 있음)이면 None.

    Example:
        >>> detect_text_encoding("日本語のテキスト".encode("shift_jis"))
        'shift_jis'
        >>> detect_text_encoding("café “quoted”".encode("cp1252"))
        'cp1252'
    """
    body = buf.rstrip(b"\x00")
    if not body:
        return None
    start = (0, 1, 2, 3) if partial else (0,)

    if not partial:
        bom = detect_bom_encoding(body)
        if bom:
            return bom

    legacy = _NUL_RUN.sub(b"", body)
    if legacy and legacy.count(0) / len(legacy) <= MAX_LEGACY_NUL_RATIO:
        for enc in legacy_encodings:
            text = decode_tolerant(legacy, enc, trim_start=start)
            need = STRICT_PRINTABLE_RATIO.get(enc, MIN_PRINTABLE_RATIO)
            if text is not None and printable_ratio(text) >= need:
                return enc

    return detect_utf16_without_bom(body, partial=partial)
