# forensic_analyzer/validate.py
"""인벤토리 검증과 기준본 비교.

두 가지를 검사한다.

1. 기본 검증(``validate_inventory_rows``): 이번 실행에서 만든 인벤토리 자체가
   온전한지. 필수 값 누락, 읽기 실패, 해시 도중 변경, 수상한 시각, 확장자 위장 등.
2. 기준본 비교(``compare_with_baseline``): 예전에 저장한 인벤토리(기준본)와 지금
   상태가 같은지. 삭제·추가·이동·내용 변경을 찾는다. "수집 당시와 지금이 같은가"를
   증명하는 기능이다.

이슈 심각도:
    - ERROR: 증거 무결성이 깨졌거나 기록이 불완전함(내용 변경, 삭제, 필수 값 누락)
    - WARN: 확인이 필요함(위장 의심, 검증 불가, 메타데이터 변경)
    - INFO: 참고 사항
"""
from __future__ import annotations

import csv
import json
import math
import os
import random
import time
import unicodedata
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple, Union

from .foroutput import meta_path_for, unescape_formula
from .hashing import HASH_CHANGED_DURING, HASH_READ_ERROR, compute_file_hashes

# 기준본과 현재 스캔에서 같아야 하는 스캔 옵션. 다르면 가짜 추가·삭제·크기 변경이 나온다.
COMPARED_SCAN_OPTIONS: Tuple[str, ...] = ("follow_symlinks", "exclude", "excluded_paths")

# 현재 시각보다 이만큼(초) 이상 미래인 시각은 조작 의심으로 본다(시간대·시계 오차 여유 1일).
FUTURE_TOLERANCE_SEC = 86400

ISSUE_FIELDS: Tuple[str, ...] = ("severity", "code", "path", "field", "value", "detail")


@dataclass(frozen=True)
class Issue:
    """검증에서 발견한 문제 한 건.

    Attributes:
        path: 관련 파일 경로(없으면 빈 문자열).
        code: 이슈 코드(예: ``HASH_CHANGED``).
        severity: ``ERROR`` / ``WARN`` / ``INFO``.
        detail: 사람이 읽을 수 있는 설명.
        field: 관련 열 이름(있으면).
        value: 문제가 된 값(있으면).
    """

    path: str
    code: str
    severity: str
    detail: str
    field: str = ""
    value: str = ""


def validate_inventory_rows(
    rows: List[Dict[str, object]],
    *,
    follow_symlinks: bool = False,
    hash_algorithms: Sequence[str] = (),
    check_file_exists: bool = True,
    check_size_matches: bool = True,
) -> List[Issue]:
    """이번 실행에서 만든 인벤토리 행을 검사한다.

    검사 항목과 이슈 코드:
        - ``MISSING_FIELD`` (ERROR): 필수 열(경로·이름·크기·수정/접근 시각)이 비어 있음
        - ``FILE_NOT_FOUND`` (ERROR): 검증 시점에 파일에 접근할 수 없음
        - ``SIZE_MISMATCH`` (WARN): 기록한 크기와 지금 크기가 다름
        - ``TS_BAD_TYPE`` (WARN): 시각 값이 숫자가 아님
        - ``TS_SUSPICIOUS`` (WARN): 시각이 0 이하(1970-01-01 이전 또는 초기화) — 조작 의심
        - ``TS_FUTURE`` (WARN): 시각이 현재보다 하루 이상 미래 — 조작 또는 시계 오류 의심
        - ``DUP_PATH`` (WARN): 같은 경로가 여러 번 기록됨
        - ``HASH_READ_FAIL`` (WARN): 해시를 계산하려 했지만 파일을 읽지 못함
        - ``CHANGED_DURING_HASH`` (WARN): 인벤토리 수집과 해시 계산 사이에 파일이 바뀜
        - ``SIGNATURE_READ_FAIL`` (WARN): 시그니처 판별을 위해 파일을 읽지 못함
        - ``EXT_MISMATCH`` (WARN): 확장자와 실제 내용이 다름(위장 의심)
        - ``LINK_BROKEN`` (INFO): 가리키는 대상이 없는 심볼릭 링크

    Args:
        rows: 인벤토리 행(해시·시그니처 열이 있으면 함께 검사).
        follow_symlinks: 인벤토리를 만들 때와 같은 값. 크기 비교 시 stat 방식을 맞춘다.
        hash_algorithms: 이번 실행에서 계산한 해시 알고리즘. 비어 있으면 해시 검사를 생략한다.
        check_file_exists: 파일 존재 여부를 다시 확인할지.
        check_size_matches: 크기를 다시 확인할지.

    Returns:
        이슈 리스트.
    """
    issues: List[Issue] = []
    required = ("path", "name", "size_bytes", "mtime_epoch", "atime_epoch")
    future_limit = time.time() + FUTURE_TOLERANCE_SEC
    seen: Dict[str, int] = {}

    for r in rows:
        p = str(r.get("path", "") or "")
        seen[p] = seen.get(p, 0) + 1

        for f in required:
            if r.get(f) in (None, ""):
                issues.append(Issue(p, "MISSING_FIELD", "ERROR", "필수 값 누락", field=f))

        if p and (check_file_exists or check_size_matches):
            try:
                st = os.stat(p) if follow_symlinks else os.lstat(p)
            except OSError:
                if check_file_exists:
                    issues.append(Issue(p, "FILE_NOT_FOUND", "ERROR", "파일에 접근할 수 없거나 존재하지 않음"))
            else:
                recorded = _to_int(r.get("size_bytes"))
                if check_size_matches and recorded is not None and not r.get("link_broken") and st.st_size != recorded:
                    issues.append(Issue(p, "SIZE_MISMATCH", "WARN", f"실제({st.st_size}) ≠ 기록({recorded})",
                                        field="size_bytes", value=str(recorded)))

        for tf in ("mtime_epoch", "atime_epoch", "ctime_epoch", "birthtime_epoch"):
            v = r.get(tf)
            if v in (None, ""):
                continue  # 필수 열 누락은 위에서, 선택 열(ctime·birthtime)은 OS별로 없을 수 있음
            fv = _to_float(v)
            if fv is None or not math.isfinite(fv):
                issues.append(Issue(p, "TS_BAD_TYPE", "WARN", "시각 값이 숫자가 아님", field=tf, value=str(v)))
            elif fv <= 0:
                issues.append(Issue(p, "TS_SUSPICIOUS", "WARN",
                                    "시각이 0 이하(1970-01-01 이전 또는 초기화) — 조작 의심", field=tf, value=str(v)))
            elif fv > future_limit:
                issues.append(Issue(p, "TS_FUTURE", "WARN",
                                    "시각이 현재보다 하루 이상 미래 — 조작 또는 시계 오류 의심", field=tf, value=str(v)))

        status = r.get("hash_status")
        if hash_algorithms and status == HASH_READ_ERROR:
            issues.append(Issue(p, "HASH_READ_FAIL", "WARN", "해시 계산을 위해 파일을 읽지 못함"))
        if status == HASH_CHANGED_DURING:
            issues.append(Issue(p, "CHANGED_DURING_HASH", "WARN",
                                "인벤토리 수집과 해시 계산 사이에 크기·수정 시각이 바뀜(해시 시점 불확실)"))
        if r.get("sig_source") == "error":
            issues.append(Issue(p, "SIGNATURE_READ_FAIL", "WARN", "시그니처 판별을 위해 파일을 읽지 못함"))
        if r.get("ext_mismatch") is True:
            issues.append(Issue(p, "EXT_MISMATCH", "WARN",
                                f"확장자({r.get('ext_on_disk') or '없음'})와 실제 내용 불일치: "
                                f"{r.get('sig_mime')} / {r.get('sig_desc')}",
                                field="ext_mismatch", value="True"))
        if r.get("link_broken") is True:
            issues.append(Issue(p, "LINK_BROKEN", "INFO", f"대상이 없는 심볼릭 링크 → {r.get('link_target', '')}"))

    for p, count in seen.items():
        if p and count > 1:
            issues.append(Issue(p, "DUP_PATH", "WARN", f"같은 경로가 {count}번 기록됨"))
    return issues


def sample_verify_hashes(
    rows: List[Dict[str, object]],
    *,
    algorithms: Tuple[str, ...] = ("md5", "sha256"),
    sample_ratio: float = 0.05,
    sample_min: int = 5,
    sample_max: int = 200,
    chunk_size: int = 1024 * 1024,
    seed: int = 0,
) -> List[Issue]:
    """일부 파일의 해시를 다시 계산해, 같은 실행 안에서 계산 결과가 일관적인지 확인한다.

    같은 실행 안에서의 재계산이라 "시간이 지난 뒤의 변경"은 잡지 못한다. 그건
    ``compare_with_baseline``의 역할이다. 이 검사는 저장 매체의 읽기 오류처럼 같은
    파일을 두 번 읽었을 때 결과가 달라지는 문제를 찾는다. 표본은 ``seed``로 고정해
    같은 입력이면 항상 같은 파일을 검사한다(보고서 재현성).

    Args:
        rows: 해시 열이 있는 인벤토리 행.
        algorithms: 비교할 알고리즘.
        sample_ratio: 표본 비율.
        sample_min: 최소 표본 수.
        sample_max: 최대 표본 수.
        chunk_size: 해시 계산 시 읽기 단위.
        seed: 표본 추출 난수 시드.

    Returns:
        이슈 리스트. 코드는 ``HASH_VERIFY_FAIL`` (ERROR), ``HASH_VERIFY_READ_FAIL`` (WARN).
    """
    candidates = [r for r in rows if r.get("path") and any(r.get(a) for a in algorithms)]
    if not candidates:
        return []
    k = min(max(int(len(candidates) * sample_ratio), sample_min), sample_max, len(candidates))
    sample = random.Random(seed).sample(candidates, k)

    issues: List[Issue] = []
    for r in sample:
        p = str(r["path"])
        result = compute_file_hashes(p, algorithms, chunk_size=chunk_size)
        if result is None:
            issues.append(Issue(p, "HASH_VERIFY_READ_FAIL", "WARN", "재계산을 위해 파일을 읽지 못함"))
            continue
        for algo in algorithms:
            expected = str(r.get(algo) or "").lower()
            if expected and expected != result[algo].lower():
                issues.append(Issue(p, "HASH_VERIFY_FAIL", "ERROR",
                                    f"{algo} 재계산 불일치: {expected[:12]}… → {result[algo][:12]}…",
                                    field=algo, value=expected))
    return issues


def load_inventory_csv(csv_path: Union[str, Path]) -> List[Dict[str, str]]:
    """이전에 저장한 인벤토리 CSV(기준본)를 읽는다.

    인벤토리 CSV가 아닌 파일(README 등)을 기준본으로 주면 모든 파일이 "새로 생김"으로
    나와 결과를 오해하게 된다. 그래서 필수 열이 없으면 오류로 처리한다. 저장할 때
    수식 주입 방지용으로 붙인 작은따옴표는 떼어 원래 값으로 되돌린다.

    Args:
        csv_path: ``inventory`` 명령이 만든 CSV 경로.

    Returns:
        CSV 각 행을 딕셔너리로 담은 리스트. 값은 모두 문자열이다.

    Raises:
        FileNotFoundError: 파일이 없을 때.
        ValueError: 인벤토리 CSV 형식이 아닐 때(``path``/``rel_path``, ``size_bytes``,
            ``mtime_epoch`` 열 필요) 또는 텍스트 CSV가 아닐 때.
    """
    try:
        with open(csv_path, encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            fields = set(reader.fieldnames or [])
            rows = [{k: unescape_formula(v) if isinstance(v, str) else v for k, v in r.items()} for r in reader]
    except UnicodeDecodeError:
        raise ValueError(f"기준본이 텍스트 CSV가 아닙니다: {csv_path}")
    except csv.Error as e:
        raise ValueError(f"기준본 CSV를 해석할 수 없습니다({e}): {csv_path}")

    if not ({"path", "rel_path"} & fields) or not {"size_bytes", "mtime_epoch"} <= fields:
        raise ValueError(
            f"기준본이 inventory CSV 형식이 아닙니다(path·size_bytes·mtime_epoch 열 필요): {csv_path}"
        )
    return rows


def compare_with_baseline(
    current_rows: List[Dict[str, object]],
    baseline_rows: List[Dict[str, str]],
    *,
    algorithms: Tuple[str, ...] = ("md5", "sha256"),
    mtime_tolerance: float = 1e-3,
) -> List[Issue]:
    """기준본(예전 인벤토리)과 현재 상태를 비교해 달라진 점을 이슈로 만든다.

    파일은 ``rel_path``(루트 기준 상대 경로)로 짝짓는다. 그래서 증거 폴더를 다른
    위치로 옮겨도 비교할 수 있다. 기준본에 ``rel_path``가 없으면(구버전 CSV) 절대
    경로로 짝짓는다. 짝지을 때는 유니코드 NFC로 정규화한다. macOS는 한글 파일명을
    자모 분리형(NFD)으로 저장하는 경우가 있어, 같은 이름이 OS에 따라 다른 바이트열이
    되기 때문이다(결과 CSV에는 원래 이름을 그대로 남긴다).

    해시 비교는 기준본과 현재 양쪽에 **값이 채워진** 알고리즘으로만 한다. 열만 있고
    값이 비어 있으면 비교하지 않는다. 비교할 해시가 하나도 없으면 내용 무결성을
    검증하지 못한 것이므로 ``BASELINE_NO_HASH``를 WARN으로 남긴다.

    이동 판정은 보수적으로 한다. 사라진 파일과 새 파일의 해시가 같고, 그 해시를 가진
    후보가 양쪽에 **각각 하나뿐**이며, 크기가 0이 아닐 때만 ``MOVED``로 묶는다. 빈 파일은
    모두 해시가 같고, 같은 내용의 복사본이 여러 개면 무엇이 무엇으로 옮겨졌는지 알 수
    없기 때문이다. 그런 경우는 삭제(ERROR)와 추가(WARN)로 그대로 둔다.

    Args:
        current_rows: 지금 수집한 인벤토리 행.
        baseline_rows: ``load_inventory_csv``로 읽은 기준본 행.
        algorithms: 비교 후보 해시 알고리즘.
        mtime_tolerance: 수정 시각 비교 허용 오차(초).

    Returns:
        이슈 리스트. 코드는 다음과 같다.

        - ``BASELINE_MISSING`` (ERROR): 기준본에 있던 파일이 사라짐
        - ``HASH_CHANGED`` (ERROR): 내용이 바뀜
        - ``BASELINE_NEW`` (WARN): 기준본에 없던 파일이 생김
        - ``MOVED`` (WARN): 내용은 같고 경로만 바뀜
        - ``SIZE_CHANGED`` / ``MTIME_CHANGED`` (WARN): 크기·수정 시각이 바뀜
        - ``LINK_TARGET_CHANGED`` (WARN): 심볼릭 링크가 가리키는 대상이 바뀜
        - ``BASELINE_NO_HASH`` (WARN): 양쪽에 값이 있는 공통 해시가 없어 내용 검증 불가
        - ``HASH_NOT_COMPARED`` (WARN): 해당 파일의 해시가 한쪽에 없어 내용 비교 불가
    """
    use_rel = bool(baseline_rows) and "rel_path" in baseline_rows[0]
    key = "rel_path" if use_rel else "path"
    base_map = {_nfc(r.get(key)): r for r in baseline_rows if r.get(key)}
    cur_map = {_nfc(r.get(key)): r for r in current_rows if r.get(key)}

    common = [a for a in sorted(algorithms, key=lambda a: a != "sha256")
              if any(r.get(a) for r in baseline_rows) and any(r.get(a) for r in current_rows)]

    issues: List[Issue] = []
    if not common:
        issues.append(Issue(
            "", "BASELINE_NO_HASH", "WARN",
            "기준본과 현재 양쪽에 값이 있는 공통 해시가 없어 내용 무결성을 검증하지 못함. "
            "크기·수정 시각까지 맞춘 변조는 탐지할 수 없음. 같은 알고리즘으로 --with-hash 기준본을 만들 것",
        ))

    missing = sorted(base_map.keys() - cur_map.keys())
    new = sorted(cur_map.keys() - base_map.keys())

    if common:
        algo = common[0]
        miss_by_hash = _group_by_hash(missing, base_map, algo)
        new_by_hash = _group_by_hash(new, cur_map, algo)
        moved_src, moved_dst = set(), set()
        for h, srcs in miss_by_hash.items():
            dsts = new_by_hash.get(h, [])
            if len(srcs) == 1 and len(dsts) == 1 and _to_int(base_map[srcs[0]].get("size_bytes")) not in (None, 0):
                src, dst = srcs[0], dsts[0]
                moved_src.add(src)
                moved_dst.add(dst)
                issues.append(Issue(_shown(cur_map[dst], dst), "MOVED", "WARN", f"경로 변경(내용 동일): {src} → {dst}"))
        missing = [k for k in missing if k not in moved_src]
        new = [k for k in new if k not in moved_dst]

    for k in missing:
        issues.append(Issue(_shown(base_map[k], k), "BASELINE_MISSING", "ERROR", f"기준본에 있던 파일이 없음: {k}"))
    for k in new:
        issues.append(Issue(_shown(cur_map[k], k), "BASELINE_NEW", "WARN", f"기준본에 없던 파일이 새로 생김: {k}"))

    for k in sorted(base_map.keys() & cur_map.keys()):
        b, c = base_map[k], cur_map[k]
        shown = _shown(c, k)

        compared = False
        for algo in common:
            bh, ch = str(b.get(algo) or "").lower(), str(c.get(algo) or "").lower()
            if bh and ch:
                compared = True
                if bh != ch:
                    issues.append(Issue(shown, "HASH_CHANGED", "ERROR", f"{algo} 변경: {bh[:12]}… → {ch[:12]}…",
                                        field=algo, value=bh))
        is_link = str(c.get("is_symlink")).lower() == "true"
        if common and not compared and not is_link:
            issues.append(Issue(shown, "HASH_NOT_COMPARED", "WARN",
                                "기준본 또는 현재 쪽 해시 값이 비어 있어 내용 비교를 못 함(읽기 실패 등)"))

        bs, cs = _to_int(b.get("size_bytes")), _to_int(c.get("size_bytes"))
        if bs is not None and cs is not None and bs != cs:
            issues.append(Issue(shown, "SIZE_CHANGED", "WARN", f"크기 {bs} → {cs}", field="size_bytes", value=str(bs)))

        bm, cm = _to_float(b.get("mtime_epoch")), _to_float(c.get("mtime_epoch"))
        if bm is not None and cm is not None and abs(bm - cm) > mtime_tolerance:
            issues.append(Issue(shown, "MTIME_CHANGED", "WARN", f"수정 시각 {bm} → {cm}",
                                field="mtime_epoch", value=str(bm)))

        bl, cl = str(b.get("link_target") or ""), str(c.get("link_target") or "")
        if (bl or cl) and bl != cl:
            issues.append(Issue(shown, "LINK_TARGET_CHANGED", "WARN", f"링크 대상 {bl or '(없음)'} → {cl or '(없음)'}",
                                field="link_target", value=bl))
    return issues


def load_scan_meta(csv_path: Union[str, Path]) -> Optional[Dict[str, object]]:
    """인벤토리 CSV에 딸린 스캔 정보(``<이름>.meta.json``)를 읽는다.

    Args:
        csv_path: 인벤토리 CSV 경로.

    Returns:
        스캔 정보 딕셔너리. 파일이 없거나 JSON이 아니면 None.
    """
    try:
        with open(meta_path_for(Path(csv_path)), encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def compare_scan_options(baseline_meta: Optional[Dict[str, object]], current_meta: Dict[str, object]) -> List[Issue]:
    """기준본을 만들 때와 지금의 스캔 옵션이 같은지 확인한다.

    심볼릭 링크를 따라갔는지, 무엇을 제외했는지가 다르면 실제로는 바뀌지 않은 파일이
    추가·삭제·크기 변경으로 나온다. 그런 결과를 오해하지 않도록 옵션 차이를 먼저 알린다.
    기준본 폴더 위치(``root``)는 증거를 옮겨도 비교할 수 있어야 하므로 비교하지 않는다.

    Args:
        baseline_meta: ``load_scan_meta``로 읽은 기준본 스캔 정보. 없으면 None.
        current_meta: 지금 스캔의 정보.

    Returns:
        이슈 리스트. 코드는 ``BASELINE_OPTIONS_DIFFER`` (WARN), ``BASELINE_META_MISSING`` (INFO).
    """
    if baseline_meta is None:
        return [Issue("", "BASELINE_META_MISSING", "INFO",
                      "기준본의 스캔 정보(.meta.json)가 없어 스캔 옵션이 같은지 확인하지 못함")]
    issues: List[Issue] = []
    for key in COMPARED_SCAN_OPTIONS:
        b, c = baseline_meta.get(key), current_meta.get(key)
        if isinstance(b, list):
            b = sorted(map(str, b))
        if isinstance(c, list):
            c = sorted(map(str, c))
        if b != c:
            issues.append(Issue("", "BASELINE_OPTIONS_DIFFER", "WARN",
                                f"스캔 옵션 {key}가 기준본과 다름: {b} → {c}. 추가·삭제·크기 변경 결과가 "
                                "옵션 차이 때문일 수 있음", field=key, value=str(b)))
    return issues


def issues_to_rows(issues: List[Issue]) -> List[Dict[str, str]]:
    """Issue 목록을 CSV 저장용 행으로 바꾼다.

    Args:
        issues: 이슈 목록.

    Returns:
        ``ISSUE_FIELDS`` 열을 가진 행 리스트.
    """
    return [asdict(i) for i in issues]


def summarize_issues(issues: List[Issue]) -> Dict[str, int]:
    """이슈를 심각도·코드별로 집계한다.

    Args:
        issues: 이슈 목록.

    Returns:
        예: ``{"ERROR": 1, "WARN": 2, "HASH_CHANGED": 1, "MOVED": 1, "BASELINE_NEW": 1}``.
    """
    summary: Dict[str, int] = {}
    for iss in issues:
        summary[iss.severity] = summary.get(iss.severity, 0) + 1
        summary[iss.code] = summary.get(iss.code, 0) + 1
    return summary


# ---------------------------------------------------------------------------
# 내부 유틸
# ---------------------------------------------------------------------------

def _group_by_hash(keys: List[str], rows: Dict[str, Dict[str, object]], algo: str) -> Dict[str, List[str]]:
    """경로 목록을 해시 값별로 묶는다(해시가 비어 있으면 제외).

    Args:
        keys: 경로 키 목록.
        rows: 키 → 행.
        algo: 사용할 알고리즘.

    Returns:
        해시 → 경로 키 목록.
    """
    out: Dict[str, List[str]] = {}
    for k in keys:
        h = str(rows[k].get(algo) or "").lower()
        if h:
            out.setdefault(h, []).append(k)
    return out


def _nfc(value: object) -> str:
    """경로 문자열을 유니코드 NFC로 정규화한다.

    Args:
        value: 경로 값.

    Returns:
        NFC 정규화한 문자열.
    """
    return unicodedata.normalize("NFC", str(value))


def _shown(row: Dict[str, object], fallback: str) -> str:
    """이슈 CSV의 path 열 값을 고른다. 다른 이슈와 맞추기 위해 절대 경로를 우선한다.

    Args:
        row: 인벤토리 행.
        fallback: ``path``가 없을 때 쓸 값(상대 경로).

    Returns:
        표시할 경로.
    """
    return str(row.get("path") or fallback)


def _to_int(v: object) -> Optional[int]:
    """값을 정수로 바꾼다. 실패하면 None.

    Args:
        v: 변환할 값.

    Returns:
        정수 또는 None.
    """
    try:
        return int(float(v))  # type: ignore[arg-type]
    except (TypeError, ValueError, OverflowError):
        return None


def _to_float(v: object) -> Optional[float]:
    """값을 실수로 바꾼다. 실패하면 None.

    Args:
        v: 변환할 값.

    Returns:
        실수 또는 None.
    """
    try:
        return float(v)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
