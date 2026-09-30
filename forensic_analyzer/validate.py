# forensic_analyzer/validate.py
from __future__ import annotations
import csv
import math
import os
import random
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple, Union

# 내부 모듈(해시 재검증 용)
try:
    from .hashing import compute_file_hashes
except Exception:
    compute_file_hashes = None  # 선택적 의존

#데이터 모델

@dataclass(frozen=True)
class Issue:
    path: str
    code: str             # 예: MISSING_FIELD, SIZE_MISMATCH, HASH_VERIFY_FAIL …
    severity: str         # INFO / WARN / ERROR
    detail: str           # 사람이 읽을 수 있는 설명
    field: str = ""       # 관련 필드명 (있다면)
    value: str = ""       # 문제값 (있다면)


#api 호출


def validate_inventory_rows(
    rows: List[Dict[str, object]],
    *,
    required_fields: Sequence[str] = (
        "path", "name", "parent", "size_bytes",
        "mtime_epoch", "atime_epoch", "ctime_epoch",
    ),
    check_file_exists: bool = True,
    check_size_matches: bool = True,
    epoch_min: float = 0.0,  # 음수 epoch은 기본적으로 이상치로 간주
    allow_missing_birthtime: bool = True,
    detect_duplicate_paths: bool = True,
) -> List[Issue]:
    """
    인벤토리/확장 컬럼을 가진 rows(list[dict])에 대해 기본 검증을 수행한다.
    - 필수 필드 존재 여부
    - 파일 존재 여부(선택)
    - size_bytes가 실제 파일 크기와 일치하는지(선택)
    - 타임스탬프(epoch) 이상치(음수/None/NaN)
    - 중복 path
    - (선택) birthtime_epoch는 OS에 따라 없을 수 있으므로 옵션으로 허용
    """
    issues: List[Issue] = []

    # 1) 필수 필드
    for r in rows:
        p = str(r.get("path", ""))
        for f in required_fields:
            if f not in r or r.get(f) in (None, ""):
                issues.append(Issue(p, "MISSING_FIELD", "ERROR", f"필수 필드 누락", field=f))

    # 2) 파일 존재 & 크기 일치
    if check_file_exists or check_size_matches:
        for r in rows:
            p = str(r.get("path", ""))
            if not p:
                continue
            try:
                st = os.lstat(p)
            except (OSError, PermissionError):
                if check_file_exists:
                    issues.append(Issue(p, "FILE_NOT_FOUND", "ERROR", "파일에 접근 불가 또는 존재하지 않음"))
                continue

            if check_size_matches:
                inv_size = _to_int_safely(r.get("size_bytes"))
                if inv_size is None:
                    issues.append(Issue(p, "SIZE_MISSING", "ERROR", "size_bytes 누락/비정상", field="size_bytes"))
                else:
                    if int(st.st_size) != int(inv_size):
                        issues.append(Issue(
                            p, "SIZE_MISMATCH", "WARN",
                            f"실제({st.st_size}) ≠ 기록({inv_size})", field="size_bytes",
                            value=str(inv_size)
                        ))

    # 3) 타임스탬프 검증
    time_fields = ["mtime_epoch", "atime_epoch", "ctime_epoch"]
    # birthtime_epoch는 OS에 따라 없을 수 있음
    if not allow_missing_birthtime:
        time_fields.append("birthtime_epoch")

    for r in rows:
        p = str(r.get("path", ""))
        for tf in time_fields:
            if tf not in r or r.get(tf) in (None, ""):
                issues.append(Issue(p, "TS_MISSING", "WARN", "타임스탬프 누락", field=tf))
                continue
            fv = _to_float_safely(r.get(tf))
            if fv is None or math.isnan(fv):
                issues.append(Issue(p, "TS_BAD_TYPE", "WARN", "타임스탬프 값이 숫자가 아님", field=tf, value=str(r.get(tf))))
                continue
            if fv < epoch_min:
                issues.append(Issue(p, "TS_OUT_OF_RANGE", "WARN", f"비정상(epoch<{epoch_min})", field=tf, value=str(fv)))

    # 4) 중복 path
    if detect_duplicate_paths:
        seen: Dict[str, int] = {}
        for r in rows:
            p = str(r.get("path", ""))
            if not p:
                continue
            seen[p] = seen.get(p, 0) + 1
        for p, count in seen.items():
            if count > 1:
                issues.append(Issue(p, "DUP_PATH", "WARN", f"중복 path {count}개"))

    # 5) 시그니처-확장자 불일치 표시(있다면)
    for r in rows:
        p = str(r.get("path", ""))
        ext_mismatch = r.get("ext_mismatch")
        if isinstance(ext_mismatch, bool) and ext_mismatch:
            issues.append(Issue(p, "EXT_MISMATCH", "INFO", "확장자와 시그니처 불일치", field="ext_mismatch", value="True"))

    return issues


def sample_verify_hashes(
    rows: List[Dict[str, object]],
    *,
    algorithms: Tuple[str, ...] = ("md5", "sha256"),
    sample_ratio: float = 0.05,       # 전체의 5% 샘플링
    sample_min: int = 5,
    sample_max: int = 200,
    chunk_size: int = 1024 * 1024,
    missing_as: str = "",
) -> List[Issue]:
    """
    인벤토리 rows 중 일부 샘플을 골라 해시를 재계산하여 CSV의 해시와 일치하는지 검증한다.
    - rows[*]['path']와 rows[*][algo] (예: 'md5','sha256')가 존재한다고 가정
    - compute_file_hashes가 사용 가능할 때만 동작. 불가 시 INFO 이슈 한 건으로 통보.
    """
    issues: List[Issue] = []

    if compute_file_hashes is None:
        issues.append(Issue("", "HASH_VERIFY_SKIPPED", "INFO", "compute_file_hashes 사용 불가(모듈 import 실패)"))
        return issues

    # 샘플 구성
    candidates = [r for r in rows if r.get("path")]
    n = len(candidates)
    if n == 0:
        return issues

    k = min(max(int(n * sample_ratio), sample_min), sample_max)
    sample = random.sample(candidates, k) if n > k else candidates

    for r in sample:
        p = str(r.get("path"))
        try:
            result = compute_file_hashes(p, algorithms=algorithms, chunk_size=chunk_size)
        except ValueError as e:
            # 지원하지 않는 알고리즘 등
            issues.append(Issue(p, "HASH_VERIFY_ERROR", "ERROR", f"해시 계산 실패: {e}"))
            continue

        if result is None:
            issues.append(Issue(p, "HASH_VERIFY_READ_FAIL", "WARN", "파일 읽기 실패(권한/손상 등)"))
            continue

        for algo in algorithms:
            expected = str(r.get(algo, missing_as) or missing_as)
            actual = result.get(algo, missing_as) or missing_as
            if not expected:
                issues.append(Issue(p, "HASH_EXPECTED_MISSING", "WARN", f"{algo} 값 누락", field=algo))
                continue
            if not actual:
                issues.append(Issue(p, "HASH_ACTUAL_MISSING", "WARN", f"{algo} 재계산 실패", field=algo))
                continue
            if expected.lower() != actual.lower():
                issues.append(Issue(
                    p, "HASH_VERIFY_FAIL", "ERROR",
                    f"{algo} 불일치: expected={expected[:12]}… actual={actual[:12]}…",
                    field=algo, value=expected
                ))
    return issues


def load_inventory_csv(csv_path: Union[str, Path]) -> List[Dict[str, str]]:
    """이전에 저장한 인벤토리 CSV(기준본)를 읽어 행 리스트로 반환한다.

    Args:
        csv_path: ``inventory`` 명령이 만든 CSV 경로.

    인벤토리 CSV가 아닌 파일(README 등)을 기준본으로 잘못 주면, 모든 파일이
    "새로 생김"으로 나와 결과를 오해하게 된다. 그래서 필수 열이 없으면 오류로 처리한다.

    Returns:
        CSV 각 행을 딕셔너리로 담은 리스트. 값은 모두 문자열이다.

    Raises:
        FileNotFoundError: 파일이 없을 때.
        ValueError: 인벤토리 CSV 형식이 아닐 때(``path``/``rel_path``, ``size_bytes``,
            ``mtime_epoch`` 열이 없음).
    """
    try:
        with open(csv_path, encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            fields = set(reader.fieldnames or [])
            rows = list(reader)
    except UnicodeDecodeError:
        raise ValueError(f"기준본이 텍스트 CSV가 아닙니다: {csv_path}")

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

    "수집 당시와 지금이 같은가"를 확인하는 기능이다. 같은 실행 안에서 방금 계산한
    값끼리 비교하는 ``sample_verify_hashes``와 달리, 시간이 지난 뒤의 변조·삭제·추가를
    잡아낼 수 있다.

    파일은 ``rel_path``(루트 기준 상대 경로)로 짝을 짓는다. 기준본에 ``rel_path`` 열이
    없으면(이전 버전 CSV) 절대 경로 ``path``로 짝을 짓는다.

    Args:
        current_rows: 지금 수집한 인벤토리 행.
        baseline_rows: ``load_inventory_csv``로 읽은 기준본 행.
        algorithms: 비교할 해시 알고리즘. 양쪽에 모두 값이 있을 때만 비교한다.
        mtime_tolerance: 수정 시각 비교 허용 오차(초). CSV 저장 시 반올림을 흡수한다.

    Returns:
        이슈 리스트. 코드는 다음과 같다.

        - ``BASELINE_MISSING`` (ERROR): 기준본에 있던 파일이 사라짐
        - ``BASELINE_NEW`` (WARN): 기준본에 없던 파일이 생김
        - ``MOVED`` (WARN): 같은 해시의 파일이 경로만 바뀜(MISSING+NEW 대신 기록)
        - ``HASH_CHANGED`` (ERROR): 해시가 달라짐(내용 변경)
        - ``SIZE_CHANGED`` (WARN): 크기가 달라짐
        - ``MTIME_CHANGED`` (WARN): 수정 시각이 달라짐
        - ``BASELINE_NO_HASH`` (WARN): 공통 해시 열이 없어 내용 무결성을 검증하지 못함
        - ``HASH_NOT_COMPARED`` (WARN): 해당 파일의 해시 값이 비어 비교하지 못함

    Example:
        >>> base = load_inventory_csv("outputs/inventory_case01.csv")
        >>> issues = compare_with_baseline(current_rows, base)
        >>> [i.code for i in issues]
        ['HASH_CHANGED', 'BASELINE_NEW']
    """
    use_rel = bool(baseline_rows) and "rel_path" in baseline_rows[0]
    key = "rel_path" if use_rel else "path"
    base_map = {str(r.get(key, "")): r for r in baseline_rows if r.get(key)}
    cur_map = {str(r.get(key, "")): r for r in current_rows if r.get(key)}

    # 양쪽 모두에 열이 있는 알고리즘만 비교 대상이다(sha256을 md5보다 우선).
    base_cols = set(baseline_rows[0].keys()) if baseline_rows else set()
    cur_cols = set(current_rows[0].keys()) if current_rows else set()
    common_algos = [a for a in sorted(algorithms, key=lambda a: a != "sha256")
                    if a in base_cols and a in cur_cols]

    issues: List[Issue] = []
    if not common_algos:
        issues.append(Issue(
            "", "BASELINE_NO_HASH", "WARN",
            "기준본과 현재 인벤토리에 공통 해시 열이 없어 내용 무결성을 검증하지 못함 "
            "(크기·수정 시각까지 맞춘 변조는 탐지 불가). 같은 알고리즘으로 --with-hash 기준본을 만들 것",
        ))

    missing = sorted(base_map.keys() - cur_map.keys())
    new = sorted(cur_map.keys() - base_map.keys())

    # 이동 탐지: 사라진 파일과 새 파일의 해시가 같으면 "이동"으로 묶는다.
    if common_algos:
        algo = common_algos[0]
        new_by_hash: Dict[str, List[str]] = {}
        for k in new:
            h = str(cur_map[k].get(algo) or "").lower()
            if h:
                new_by_hash.setdefault(h, []).append(k)
        moved_missing, moved_new = set(), set()
        for k in missing:
            h = str(base_map[k].get(algo) or "").lower()
            if h and new_by_hash.get(h):
                dst = new_by_hash[h].pop(0)
                moved_missing.add(k)
                moved_new.add(dst)
                issues.append(Issue(_display_path(cur_map[dst], dst), "MOVED", "WARN",
                                    f"경로 변경(내용 동일): {k} → {dst}"))
        missing = [k for k in missing if k not in moved_missing]
        new = [k for k in new if k not in moved_new]

    for k in missing:
        issues.append(Issue(_display_path(base_map[k], k), "BASELINE_MISSING", "ERROR",
                            f"기준본에 있던 파일이 없음: {k}"))
    for k in new:
        issues.append(Issue(_display_path(cur_map[k], k), "BASELINE_NEW", "WARN",
                            f"기준본에 없던 파일이 새로 생김: {k}"))

    for k in sorted(base_map.keys() & cur_map.keys()):
        b, c = base_map[k], cur_map[k]
        shown = _display_path(c, k)

        compared_hash = False
        for algo in common_algos:
            bh, ch = str(b.get(algo) or "").lower(), str(c.get(algo) or "").lower()
            if bh and ch:
                compared_hash = True
                if bh != ch:
                    issues.append(Issue(shown, "HASH_CHANGED", "ERROR",
                                        f"{algo} 변경: {bh[:12]}… → {ch[:12]}…",
                                        field=algo, value=bh))
        if common_algos and not compared_hash:
            issues.append(Issue(shown, "HASH_NOT_COMPARED", "WARN",
                                "해시 값이 비어 있어(읽기 실패 등) 내용 비교를 못 함"))

        bs, cs = _to_int_safely(b.get("size_bytes")), _to_int_safely(c.get("size_bytes"))
        if bs is not None and cs is not None and bs != cs:
            issues.append(Issue(shown, "SIZE_CHANGED", "WARN", f"크기 {bs} → {cs}",
                                field="size_bytes", value=str(bs)))

        bm, cm = _to_float_safely(b.get("mtime_epoch")), _to_float_safely(c.get("mtime_epoch"))
        if bm is not None and cm is not None and abs(bm - cm) > mtime_tolerance:
            issues.append(Issue(shown, "MTIME_CHANGED", "WARN", f"수정 시각 {bm} → {cm}",
                                field="mtime_epoch", value=str(bm)))
    return issues


def _display_path(row: Dict[str, object], fallback: str) -> str:
    """이슈 CSV의 path 열에 쓸 경로를 고른다.

    다른 검증 이슈와 기준을 맞추기 위해 절대 경로(``path``)를 우선 쓰고,
    없으면 짝짓기에 쓴 키(상대 경로)를 쓴다. 상대 경로는 detail 열에 함께 남긴다.

    Args:
        row: 인벤토리 행(현재 또는 기준본).
        fallback: ``path``가 없을 때 쓸 값.

    Returns:
        표시할 경로 문자열.
    """
    return str(row.get("path") or fallback)


def write_issues_csv(
    issues: List[Issue],
    csv_path: Union[str, Path],
) -> None:
    """
    Issue 리스트를 CSV로 기록(UTF-8 with BOM; 엑셀 호환).
    """
    csv_path = Path(csv_path)
    csv_path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = ["severity", "code", "path", "field", "value", "detail"]
    with open(csv_path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for iss in issues:
            row = asdict(iss)
            # 보기 좋게 컬럼 순서 맞추기
            ordered = {k: row.get(k, "") for k in fieldnames}
            w.writerow(ordered)


def summarize_issues(issues: List[Issue]) -> Dict[str, int]:
    """
    이슈를 수준/코드별로 집계해 요약 카운트를 반환.
    예: {"ERROR": 10, "WARN": 32, "INFO": 5, "HASH_VERIFY_FAIL": 2, ...}
    """
    summary: Dict[str, int] = {}
    for iss in issues:
        summary[iss.severity] = summary.get(iss.severity, 0) + 1
        summary[iss.code] = summary.get(iss.code, 0) + 1
    return summary


#내부 함수 부분


def _to_int_safely(v: object) -> Optional[int]:
    try:
        return int(v)  # float도 int로 안전 캐스팅
    except (TypeError, ValueError):
        return None

def _to_float_safely(v: object) -> Optional[float]:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None
