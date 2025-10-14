from __future__ import annotations
import csv
import fnmatch
import os
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Tuple, Union

# api 작성

def collect_inventory(
    root: Union[str, Path],
    *,
    follow_symlinks: bool = False,
    exclude_globs: Optional[Iterable[str]] = None,
) -> List[Dict[str, Union[str, int, float, None]]]:
    """
    지정한 root 경로 아래 모든 파일의 메타데이터(경로, 크기, 시간)를 수집해 리스트[dict]로 반환.
    - follow_symlinks: 심볼릭 링크 따라갈지 여부
    - exclude_globs: 제외할 글롭 패턴들 (예: ["*.tmp", "*.log", "*/.git/*"])
    """
    root = Path(root).resolve()
    _compiled_exclude = tuple(exclude_globs or [])

    rows: List[Dict[str, Union[str, int, float, None]]] = []
    for fpath in _iter_files(root, follow_symlinks=follow_symlinks, exclude_globs=_compiled_exclude):
        meta = _safe_stat(fpath, follow_symlinks=follow_symlinks)
        if meta is None:
            # 접근 권한/깨진 링크 등으로 실패한 경우 스킵
            continue

        row = {
            "path": str(fpath),
            "name": fpath.name,
            "parent": str(fpath.parent),
            "size_bytes": meta.st_size,
            # 시간은 epoch(float). 이후 단계에서 타임존/형식을 일괄 변환하기 쉬움
            "mtime_epoch": meta.st_mtime,   # last modified
            "atime_epoch": meta.st_atime,   # last accessed
            "ctime_epoch": meta.st_ctime,   # metadata changed(Unix) / created(Windows)
            "birthtime_epoch": _birthtime(meta),  # 일부 OS에서만 제공. 없으면 None
            "is_symlink": fpath.is_symlink(),
        }
        rows.append(row)

    return rows


def write_inventory_csv(
    rows: List[Dict[str, Union[str, int, float, None]]],
    csv_path: Union[str, Path],
) -> None:
    """
    collect_inventory 결과를 CSV로 저장.
    - 엑셀 호환을 위해 UTF-8 with BOM을 사용.
    """
    csv_path = Path(csv_path)
    csv_path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "path", "name", "parent", "size_bytes",
        "mtime_epoch", "atime_epoch", "ctime_epoch", "birthtime_epoch",
        "is_symlink",
    ]

    with open(csv_path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


# 내부 함수 목록

def _iter_files(
    root: Path,
    *,
    follow_symlinks: bool,
    exclude_globs: Tuple[str, ...],
) -> Iterator[Path]:
    """
    os.scandir 기반의 빠른 재귀 순회.
    - exclude_globs 패턴에 매칭되면 디렉터리/파일 모두 스킵.
    - 긴 경로/권한 오류는 안전하게 try/except로 무시하고 진행.
    """
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as it:
                for entry in it:
                    path = Path(entry.path)
                    # 제외 규칙
                    if _is_excluded(path, exclude_globs):
                        continue

                    if entry.is_dir(follow_symlinks=follow_symlinks):
                        stack.append(path)
                    elif entry.is_file(follow_symlinks=follow_symlinks):
                        yield path
                    else:
                        # 소켓/파이프/디바이스 파일은 스킵
                        continue
        except (PermissionError, FileNotFoundError, OSError):
            # 접근 불가/사라진 경로/디바이스 등은 조용히 패스
            continue


def _is_excluded(path: Path, patterns: Tuple[str, ...]) -> bool:
    if not patterns:
        return False
    spath = str(path)
    for pat in patterns:
        # 경로 전체/파일명 모두에 대해 글롭 검사
        if fnmatch.fnmatch(spath, pat) or fnmatch.fnmatch(path.name, pat):
            return True
    return False


def _safe_stat(path: Path, *, follow_symlinks: bool):
    try:
        return path.stat() if follow_symlinks else os.lstat(path)
    except (PermissionError, FileNotFoundError, OSError):
        return None


def _birthtime(st) -> Optional[float]:
    """
    생성 시간(epoch). 플랫폼별 지원이 다름.
    - Windows: st_ctime == 생성시간
    - macOS: getattr(st, "st_birthtime", None)
    - Linux(대부분): 제공 안 됨 → None
    """
    # Windows는 st_ctime이 생성시간 역할을 해서 별도 분기 불필요.
    # macOS 전용 birthtime이 있으면 제공
    bt = getattr(st, "st_birthtime", None)
    return float(bt) if bt is not None else None
