# forensic_analyzer/hashing.py
"""파일 해시 계산.

해시는 파일 내용의 지문이다. 한 바이트만 바뀌어도 값이 완전히 달라지므로,
수집 시점의 해시를 기록해 두면 나중에 내용이 바뀌었는지 확인할 수 있다
(``validate --baseline`` 참고).
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

CHUNK_SIZE_DEFAULT = 1024 * 1024  # 1MB

# hash_status 값
HASH_OK = "ok"
HASH_READ_ERROR = "read_error"
HASH_SYMLINK_SKIPPED = "symlink_skipped"
HASH_CHANGED_DURING = "changed_during_hash"


def compute_file_hashes(
    path: Union[str, Path],
    algorithms: Tuple[str, ...] = ("md5", "sha256"),
    *,
    chunk_size: int = CHUNK_SIZE_DEFAULT,
) -> Optional[Dict[str, str]]:
    """파일을 조각 단위로 읽으며 여러 해시를 한 번에 계산한다.

    파일 전체를 메모리에 올리지 않으므로 큰 파일도 처리할 수 있고, 여러 알고리즘을
    쓰더라도 파일은 한 번만 읽는다.

    Args:
        path: 파일 경로.
        algorithms: ``hashlib.new``가 받는 알고리즘 이름들. 소문자여야 한다.
        chunk_size: 한 번에 읽을 바이트 수. 1 이상이어야 한다.

    Returns:
        ``{"md5": "...", "sha256": "..."}``. 파일을 읽지 못하면 None.

    Raises:
        ValueError: 지원하지 않는 알고리즘 이름이거나 ``chunk_size``가 1보다 작을 때.

    Example:
        >>> compute_file_hashes("ForensicTestData/docs/notes.txt", ("sha256",))  # doctest: +SKIP
        {'sha256': 'fd3e54cc45ee...'}
    """
    if chunk_size < 1:
        # f.read(0)은 빈 바이트를 돌려주므로 모든 파일이 "빈 파일 해시"가 되어 버린다.
        raise ValueError("chunk_size는 1 이상이어야 합니다")
    hashers = {algo: hashlib.new(algo) for algo in algorithms}
    try:
        with Path(path).open("rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                for h in hashers.values():
                    h.update(chunk)
    except OSError:
        return None
    return {name: h.hexdigest() for name, h in hashers.items()}


def add_hashes_to_rows(
    rows: List[Dict[str, object]],
    *,
    algorithms: Tuple[str, ...] = ("md5", "sha256"),
    chunk_size: int = CHUNK_SIZE_DEFAULT,
    follow_symlinks: bool = False,
) -> List[Dict[str, object]]:
    """인벤토리 행마다 해시 열과 해시 상태(``hash_status``)를 추가한다.

    해시 상태:
        - ``ok``: 정상 계산
        - ``read_error``: 파일을 읽지 못함(권한, 삭제 등). 해시 칸은 비어 있다.
        - ``symlink_skipped``: 따라가지 않는 모드의 심볼릭 링크라 계산하지 않음
        - ``changed_during_hash``: 인벤토리를 만든 뒤 해시를 끝낼 때까지 사이에
          크기나 수정 시각이 바뀜. 해시는 계산됐지만 인벤토리의 메타데이터와
          같은 시점의 내용이라고 보장할 수 없다.

    Args:
        rows: ``collect_inventory`` 결과. ``path``, ``size_bytes``, ``mtime_epoch``,
            ``is_symlink`` 열을 사용한다.
        algorithms: 계산할 알고리즘 이름들.
        chunk_size: 한 번에 읽을 바이트 수.
        follow_symlinks: 인벤토리를 만들 때와 같은 값을 줘야 한다.

    Returns:
        입력 ``rows``를 제자리에서 수정해 그대로 반환한다.
    """
    for row in rows:
        p = row.get("path")
        if row.get("is_symlink") and not follow_symlinks:
            for algo in algorithms:
                row[algo] = ""
            row["hash_status"] = HASH_SYMLINK_SKIPPED
            continue

        result = compute_file_hashes(p, algorithms, chunk_size=chunk_size) if p else None
        if result is None:
            for algo in algorithms:
                row[algo] = ""
            row["hash_status"] = HASH_READ_ERROR
            continue

        for algo in algorithms:
            row[algo] = result[algo]
        row["hash_status"] = HASH_CHANGED_DURING if _changed_since_inventory(row, follow_symlinks) else HASH_OK
    return rows


def _changed_since_inventory(row: Dict[str, object], follow_symlinks: bool) -> bool:
    """해시 계산 직후의 크기·수정 시각이 인벤토리 기록과 다른지 확인한다.

    Args:
        row: 인벤토리 행.
        follow_symlinks: stat 방식을 인벤토리와 맞추기 위한 값.

    Returns:
        달라졌거나 다시 확인할 수 없으면 True.
    """
    try:
        path = str(row["path"])
        st = os.stat(path) if follow_symlinks else os.lstat(path)
        return st.st_size != int(row["size_bytes"]) or abs(st.st_mtime - float(row["mtime_epoch"])) > 1e-6
    except (OSError, KeyError, TypeError, ValueError):
        return True
