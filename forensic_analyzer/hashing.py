# forensic_analyzer/hashing.py
from __future__ import annotations
import hashlib
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple, Union

_CHUNK_SIZE_DEFAULT = 1024 * 1024  # 1MB

def compute_file_hashes(
    path: Union[str, Path],
    algorithms: Tuple[str, ...] = ("md5", "sha256"),
    *,
    chunk_size: int = _CHUNK_SIZE_DEFAULT,
) -> Optional[Dict[str, str]]:
    """
    파일을 스트리밍으로 읽어 지정한 알고리즘 해시를 계산.
    - 성공 시 {"md5": "...", "sha256": "..."} 반환
    - 접근 실패/읽기 실패 시 None
    """
    path = Path(path)
    hashers: Dict[str, "hashlib._Hash"] = {}
    try:
        for algo in algorithms:
            hashers[algo] = hashlib.new(algo)
    except ValueError:
        # 지원하지 않는 알고리즘 명
        raise

    try:
        with path.open("rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                for h in hashers.values():
                    h.update(chunk)
    except (PermissionError, FileNotFoundError, OSError):
        return None

    return {name: h.hexdigest() for name, h in hashers.items()}


def add_hashes_to_rows(
    rows: List[Dict[str, Union[str, int, float, None]]],
    *,
    algorithms: Tuple[str, ...] = ("md5", "sha256"),
    chunk_size: int = _CHUNK_SIZE_DEFAULT,
    missing_as: str = ""  # 읽기 실패 시 빈 문자열로 채움
) -> List[Dict[str, Union[str, int, float, None]]]:
    """
    inventory(행 리스트)에 md5/sha256 열을 추가해서 반환.
    - rows의 각 행에 'path' 키가 있어야 함.
    - 실패(권한, 삭제 등) 시 해당 열을 missing_as 값으로 채움.
    """
    for row in rows:
        p = row.get("path")
        if not p:
            for algo in algorithms:
                row[algo] = missing_as
            continue

        result = compute_file_hashes(p, algorithms, chunk_size=chunk_size)
        if result is None:
            for algo in algorithms:
                row[algo] = missing_as
        else:
            for algo in algorithms:
                row[algo] = result.get(algo, missing_as)
    return rows
