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
