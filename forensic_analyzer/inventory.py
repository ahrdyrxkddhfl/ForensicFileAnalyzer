# forensic_analyzer/inventory.py
"""파일 인벤토리 수집: 폴더를 순회하며 파일마다 경로·크기·시간 메타데이터를 기록한다.

다른 모든 기능(해시, 시그니처, 타임라인, 검증)은 이 인벤토리를 입력으로 쓴다.

심볼릭 링크 정책(명령 전체에서 동일):
    - 기본(``follow_symlinks=False``): 링크를 따라가지 않는다. 링크 자체를 한 행으로
      기록하고(``is_symlink=True``, ``link_target``=가리키는 경로), 크기·시간은 링크
      자체의 값(lstat)을 쓴다. 해시와 시그니처는 계산하지 않는다(대상 파일 내용을
      링크 이름으로 기록하면 사실과 다른 기록이 되기 때문이다).
    - ``follow_symlinks=True``: 링크가 가리키는 대상 기준으로 기록한다(stat). 이미
      방문한 폴더는 (장치 번호, inode)로 기억해 순환 링크에서 무한 반복하지 않는다.
      깨진 링크는 링크 자체 정보로 기록한다.
    - 두 모드 모두 대상이 없는 링크는 ``link_broken=True``로 표시한다.

플랫폼별 시간 필드:
    - ``mtime_epoch``: 마지막 수정 시각(모든 OS)
    - ``atime_epoch``: 마지막 접근 시각(모든 OS)
    - ``ctime_epoch``: 메타데이터 변경 시각. Unix(macOS·Linux)에서만 기록한다.
      Windows의 ``st_ctime``은 생성 시각이므로 여기에 넣지 않는다.
    - ``birthtime_epoch``: 생성 시각. macOS와 Windows에서 기록한다. 대부분의
      Linux(Python 표준 stat)에서는 제공되지 않아 빈 칸이다.
"""
from __future__ import annotations

import fnmatch
import os
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Set, Tuple, Union

_IS_WINDOWS = os.name == "nt"

Row = Dict[str, Union[str, int, float, bool, None]]

# 스캔 중 기록하는 항목의 종류(errors 리스트의 "kind" 값).
KIND_ERROR = "error"                  # 읽지 못함 → 확인하지 못한 것이 있다는 뜻(WARN)
KIND_SYMLINK_CYCLE = "symlink_cycle"  # 순환 링크를 막음 → 정상 동작(INFO)

# 인벤토리 CSV의 기본 열 순서.
INVENTORY_FIELDS: Tuple[str, ...] = (
    "path", "rel_path", "name", "parent", "size_bytes",
    "mtime_epoch", "atime_epoch", "ctime_epoch", "birthtime_epoch",
    "is_symlink", "link_target", "link_broken",
)


def iter_files(
    root: Union[str, Path],
    *,
    follow_symlinks: bool = False,
    exclude_globs: Optional[Iterable[str]] = None,
    exclude_paths: Optional[Iterable[Union[str, Path]]] = None,
    errors: Optional[List[Dict[str, str]]] = None,
) -> Iterator[Tuple[Path, bool]]:
    """루트 아래의 파일(과 심볼릭 링크)을 순회한다.

    ``search`` 명령도 이 함수를 그대로 써서, 명령마다 대상 파일 집합이 달라지지
    않게 한다. 결과는 경로 순으로 정렬해 내보내므로 실행할 때마다 순서가 같다.

    Args:
        root: 순회할 루트 폴더.
        follow_symlinks: 심볼릭 링크를 따라갈지 여부. 모듈 설명의 정책 참고.
        exclude_globs: 제외할 글롭 패턴. 경로는 OS와 상관없이 ``/`` 구분자로 바꿔
            비교하므로 ``*/.git/*`` 같은 패턴이 Windows에서도 동작한다.
        exclude_paths: 통째로 제외할 폴더·파일 경로. 결과 폴더(또는 결과 파일·기준본)가
            스캔 대상 안에 있을 때 이전 결과 CSV가 인벤토리에 섞이지 않게 하는 데 쓴다.
        errors: 스캔 중 생긴 일을 ``{"path", "reason", "kind"}``로 기록할 리스트. None이면
            기록하지 않는다. ``kind``는 ``error``(읽지 못함) 또는 ``symlink_cycle``(순환
            링크를 막음, 정상 동작)이다. 포렌식에서는 "없음"과 "못 읽음"을 구분해야
            하므로 조용히 건너뛰지 않고 여기에 남긴다.

    Yields:
        ``(경로, 심볼릭 링크 여부)`` 튜플.
    """
    root = Path(root)
    patterns = tuple(exclude_globs or ())
    skip_paths = {os.path.abspath(d) for d in (exclude_paths or ())}
    visited: Set[Tuple[int, int]] = set()
    if follow_symlinks:
        try:
            st = root.stat()
            visited.add((st.st_dev, st.st_ino))
        except OSError:
            pass

    stack = [root]
    found: List[Tuple[Path, bool]] = []
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as it:
                entries = sorted(it, key=lambda e: e.name)
        except OSError as e:
            if errors is not None:
                errors.append({"path": str(current), "reason": f"폴더 읽기 실패: {e.__class__.__name__}",
                               "kind": KIND_ERROR})
            continue

        for entry in entries:
            path = Path(entry.path)
            if is_excluded(path, patterns) or (skip_paths and os.path.abspath(path) in skip_paths):
                continue
            try:
                is_link = entry.is_symlink()
                if is_link and not follow_symlinks:
                    found.append((path, True))
                    continue
                if entry.is_dir(follow_symlinks=follow_symlinks):
                    if follow_symlinks:
                        st = entry.stat(follow_symlinks=True)
                        key = (st.st_dev, st.st_ino)
                        if key in visited:
                            if errors is not None:
                                errors.append({"path": str(path), "reason": "순환 링크: 이미 방문한 폴더라 건너뜀",
                                               "kind": KIND_SYMLINK_CYCLE})
                            continue
                        visited.add(key)
                    stack.append(path)
                elif entry.is_file(follow_symlinks=follow_symlinks):
                    found.append((path, is_link))
                elif is_link:
                    found.append((path, True))  # 따라가기 모드의 깨진 링크
            except OSError as e:
                if errors is not None:
                    errors.append({"path": str(path), "reason": f"항목 확인 실패: {e.__class__.__name__}",
                                   "kind": KIND_ERROR})

    found.sort(key=lambda t: str(t[0]))
    yield from found


def collect_inventory(
    root: Union[str, Path],
    *,
    follow_symlinks: bool = False,
    exclude_globs: Optional[Iterable[str]] = None,
    exclude_paths: Optional[Iterable[Union[str, Path]]] = None,
    errors: Optional[List[Dict[str, str]]] = None,
) -> List[Row]:
    """루트 아래 모든 파일의 메타데이터를 수집해 행 리스트로 반환한다.

    Args:
        root: 스캔할 루트 폴더.
        follow_symlinks: 심볼릭 링크를 따라갈지 여부. 모듈 설명의 정책 참고.
        exclude_globs: 제외할 글롭 패턴(예: ``["*.tmp", "*/.git/*"]``).
        exclude_paths: 통째로 제외할 폴더·파일 경로. ``iter_files`` 참고.
        errors: 스캔 중 생긴 일을 기록할 리스트. ``iter_files`` 참고.

    Returns:
        ``rel_path`` 순으로 정렬된 행 리스트. 각 행의 열은 ``INVENTORY_FIELDS``이며
        시간은 epoch(초, float)다.

    Example:
        >>> rows = collect_inventory("ForensicTestData")
        >>> rows[0]["rel_path"]  # doctest: +SKIP
        'binaries/archive.zip'
    """
    root = Path(root).resolve()
    rows: List[Row] = []
    for fpath, is_link in iter_files(
        root, follow_symlinks=follow_symlinks, exclude_globs=exclude_globs, exclude_paths=exclude_paths, errors=errors
    ):
        broken = False
        try:
            st = fpath.stat() if (follow_symlinks or not is_link) else os.lstat(fpath)
        except OSError:
            if not is_link:
                if errors is not None:
                    errors.append({"path": str(fpath), "reason": "메타데이터 읽기 실패", "kind": KIND_ERROR})
                continue
            try:
                st = os.lstat(fpath)  # 깨진 링크: 링크 자체 정보라도 남긴다.
                broken = True
            except OSError:
                if errors is not None:
                    errors.append({"path": str(fpath), "reason": "메타데이터 읽기 실패", "kind": KIND_ERROR})
                continue

        if is_link and not follow_symlinks and not os.path.exists(fpath):
            broken = True  # 따라가지 않아도 "대상이 없는 링크"라는 사실은 기록한다.
        created, meta_changed = platform_times(st, is_windows=_IS_WINDOWS)
        rows.append({
            "path": str(fpath),
            "rel_path": fpath.relative_to(root).as_posix(),
            "name": fpath.name,
            "parent": str(fpath.parent),
            "size_bytes": st.st_size,
            "mtime_epoch": st.st_mtime,
            "atime_epoch": st.st_atime,
            "ctime_epoch": meta_changed,
            "birthtime_epoch": created,
            "is_symlink": is_link,
            "link_target": _read_link(fpath) if is_link else "",
            "link_broken": broken,
        })
    return rows


def platform_times(st: os.stat_result, *, is_windows: bool) -> Tuple[Optional[float], Optional[float]]:
    """OS별로 의미가 다른 stat 시간을 (생성 시각, 메타데이터 변경 시각)으로 정리한다.

    ``st_ctime``의 뜻이 OS마다 달라서 그대로 쓰면 타임라인 라벨이 틀린다.

    - Windows: ``st_ctime`` = 생성 시각. 메타데이터 변경 시각은 제공되지 않는다.
      Python 3.12 이상은 ``st_birthtime``도 제공하므로 있으면 그것을 쓴다.
    - macOS: ``st_birthtime`` = 생성 시각, ``st_ctime`` = 메타데이터 변경 시각.
    - Linux: 생성 시각은 대개 제공되지 않고, ``st_ctime`` = 메타데이터 변경 시각.

    Args:
        st: ``os.stat``/``os.lstat`` 결과.
        is_windows: Windows 규칙을 적용할지 여부.

    Returns:
        ``(생성 시각 또는 None, 메타데이터 변경 시각 또는 None)``.
    """
    birth = getattr(st, "st_birthtime", None)
    if is_windows:
        return (float(birth) if birth is not None else float(st.st_ctime)), None
    return (float(birth) if birth is not None else None), float(st.st_ctime)


def is_excluded(path: Path, patterns: Tuple[str, ...]) -> bool:
    """경로가 제외 패턴 중 하나와 일치하는지 확인한다.

    경로 전체(``/`` 구분자)와 파일 이름 양쪽에 대해 검사한다.

    Args:
        path: 검사할 경로.
        patterns: 글롭 패턴 목록.

    Returns:
        하나라도 일치하면 True.

    Example:
        >>> is_excluded(Path("/case/.git/config"), ("*/.git/*",))
        True
    """
    if not patterns:
        return False
    posix = path.as_posix()
    for pat in patterns:
        if fnmatch.fnmatch(posix, pat) or fnmatch.fnmatch(path.name, pat):
            return True
    return False


def _read_link(path: Path) -> str:
    """심볼릭 링크가 가리키는 경로 문자열을 읽는다.

    Args:
        path: 심볼릭 링크 경로.

    Returns:
        링크 대상 문자열. 읽지 못하면 빈 문자열.
    """
    try:
        return os.readlink(path)
    except OSError:
        return ""
