# forensic_analyzer/foroutput.py
"""결과 CSV 저장 공용 유틸리티.

모든 명령(inventory / search / timeline / validate)의 결과는 이 모듈로 저장한다.
저장 방식을 한곳에 모아 두면 인코딩, 열 순서, 빈 결과 처리 방식이 명령마다
달라지지 않는다.
"""
from __future__ import annotations

import csv
import datetime
import os
import re
import tempfile
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Optional, Sequence


# 엑셀이 수식으로 해석하는 첫 글자. 파일명은 증거 제작자가 마음대로 정할 수 있으므로,
# "=HYPERLINK(...)" 같은 이름이 결과 CSV를 여는 분석가의 PC에서 수식으로 실행되지 않게 막는다.
FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")
FORMULA_ESCAPE = "'"


def ensure_dir(path: Path) -> Path:
    """폴더가 없으면 만들고 그 경로를 반환한다.

    Args:
        path: 만들 폴더 경로.

    Returns:
        입력받은 ``path`` 그대로.
    """
    path.mkdir(parents=True, exist_ok=True)
    return path


def make_outpath(tool: str, out_dir: Path, label: Optional[str], suffix: str = "csv") -> Path:
    """``<명령>_<라벨>_<YYYYmmdd_HHMMSS>.<확장자>`` 형태의 결과 파일 경로를 만든다.

    실행 시각을 붙이고, 같은 이름이 이미 있으면 ``_2``, ``_3``을 붙여 이전 결과를
    덮어쓰지 않는다.

    Args:
        tool: 명령 이름(예: ``inventory``).
        out_dir: 결과 폴더.
        label: 파일명에 붙일 사건 라벨. 비어 있으면 생략하며, ``sanitize_label``로 정리한다.
        suffix: 확장자.

    Returns:
        결과 파일 경로.

    Example:
        >>> make_outpath("inventory", Path("outputs"), "case01").name  # doctest: +SKIP
        'inventory_case01_20260930_101500.csv'
    """
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = sanitize_label(label or "")
    base = f"{tool}_{safe}_{ts}" if safe else f"{tool}_{ts}"
    candidate = out_dir / f"{base}.{suffix}"
    n = 2
    while candidate.exists():  # 같은 초에 다시 실행해도 이전 결과를 덮어쓰지 않는다.
        candidate = out_dir / f"{base}_{n}.{suffix}"
        n += 1
    return candidate


def sanitize_label(label: str) -> str:
    """라벨을 파일명에 안전한 문자만 남기도록 바꾼다.

    ``../../x`` 같은 라벨로 결과 파일이 결과 폴더 밖에 저장되는 것을 막는다.

    Args:
        label: 사용자가 준 라벨.

    Returns:
        영문·숫자·한글·``.``·``_``·``-`` 외의 문자를 ``_``로 바꾼 문자열.

    Example:
        >>> sanitize_label("../../escape")
        '.._.._escape'
    """
    return re.sub(r"[^0-9A-Za-z가-힣._-]", "_", label)


def escape_formula(value: object) -> object:
    """엑셀 수식으로 해석될 수 있는 문자열 앞에 작은따옴표를 붙인다(CSV 수식 주입 방지).

    숫자 값(int·float)과 숫자로 읽히는 문자열(예: ``-1.5``)은 그대로 둔다.

    Args:
        value: CSV에 쓸 값.

    Returns:
        안전하게 바꾼 값.

    Example:
        >>> print(escape_formula('=HYPERLINK("http://x")'))
        '=HYPERLINK("http://x")
        >>> escape_formula("-1.5")
        '-1.5'
    """
    if not isinstance(value, str) or not value.startswith(FORMULA_PREFIXES):
        return value
    try:
        float(value)
        return value
    except ValueError:
        return FORMULA_ESCAPE + value


def unescape_formula(value: str) -> str:
    """``escape_formula``로 붙인 작은따옴표를 떼어 원래 값으로 되돌린다.

    Args:
        value: CSV에서 읽은 값.

    Returns:
        원래 값.
    """
    if value.startswith(FORMULA_ESCAPE) and value[1:].startswith(FORMULA_PREFIXES):
        return value[1:]
    return value


def build_fieldnames(rows: Sequence[Mapping[str, object]], preferred: Iterable[str]) -> List[str]:
    """CSV 헤더(열 순서)를 만든다.

    ``preferred`` 중 실제로 어느 행에든 들어 있는 열을 먼저 그 순서대로 두고,
    나머지 열은 처음 등장한 순서대로 뒤에 붙인다. 존재하지 않는 열은 넣지 않는다.
    예를 들어 해시를 계산하지 않았으면 ``md5``/``sha256`` 열 자체가 생기지 않으므로,
    나중에 이 CSV를 기준본으로 쓸 때 "빈 해시 열"을 "해시 있음"으로 오해하지 않는다.

    Args:
        rows: 저장할 행 목록.
        preferred: 앞쪽에 둘 열 이름 순서.

    Returns:
        열 이름 목록.
    """
    present: Dict[str, None] = {}
    for r in rows:
        for k in r.keys():
            present.setdefault(k, None)
    head = [k for k in preferred if k in present]
    tail = [k for k in present if k not in head]
    return head + tail


def write_rows_csv(
    rows: Sequence[Mapping[str, object]],
    out_path: Path,
    *,
    preferred: Iterable[str] = (),
    empty_fieldnames: Optional[Iterable[str]] = None,
) -> Path:
    """행 목록을 CSV로 원자적으로 저장한다(UTF-8 BOM, 엑셀 호환).

    임시 파일에 다 쓴 뒤 한 번에 이름을 바꾸므로, 저장 도중 중단돼도 반쯤 쓰인
    CSV가 남지 않는다. 결과가 0건이어도 헤더만 있는 CSV를 만든다. "결과 없음"과
    "실행 안 됨"을 구분하기 위해서다. 엑셀 수식으로 해석될 수 있는 문자열은
    ``escape_formula``로 무력화한다.

    Args:
        rows: 저장할 행 목록. 값은 문자열로 변환되어 저장된다.
        out_path: 저장할 경로. 상위 폴더가 없으면 만든다.
        preferred: 앞쪽에 둘 열 순서. ``build_fieldnames`` 참고.
        empty_fieldnames: 결과가 0건일 때 쓸 헤더. 없으면 ``preferred``를 쓴다.

    Returns:
        저장한 경로.

    Raises:
        OSError: 저장에 실패했을 때. 이때 임시 파일은 지우고 예외를 다시 던진다.
    """
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    preferred = list(preferred)
    if rows:
        fieldnames = build_fieldnames(rows, preferred)
    else:
        fieldnames = list(empty_fieldnames) if empty_fieldnames is not None else preferred

    fd, tmp_name = tempfile.mkstemp(dir=out_path.parent, prefix=".tmp_", suffix=".csv")
    try:
        with os.fdopen(fd, "w", encoding="utf-8-sig", newline="") as f:
            w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            w.writeheader()
            for r in rows:
                w.writerow({k: escape_formula(r.get(k, "")) for k in fieldnames})
        os.replace(tmp_name, out_path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
    return out_path
