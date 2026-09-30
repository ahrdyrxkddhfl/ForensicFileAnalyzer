"""pytest 공용 설정과 픽스처."""
from __future__ import annotations

import os
import random
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from forensic_analyzer import signature  # noqa: E402

# libmagic이 있는 환경에서는 두 판별 경로를 모두 검사한다.
MAGIC_MODES = [False, True] if signature._HAS_MAGIC else [False]


@pytest.fixture
def rng() -> random.Random:
    """고정 시드 난수 생성기. 테스트 결과가 실행마다 달라지지 않게 한다."""
    return random.Random(1234)


@pytest.fixture
def write(tmp_path: Path):
    """``write("a/b.txt", b"...")``로 임시 폴더에 파일을 만드는 헬퍼."""
    def _write(rel: str, data: bytes) -> Path:
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        return p
    return _write


def can_symlink(tmp_path: Path) -> bool:
    """이 환경에서 심볼릭 링크를 만들 수 있는지 확인한다(Windows 권한 등)."""
    try:
        os.symlink("x", tmp_path / ".probe_link")
        os.unlink(tmp_path / ".probe_link")
        return True
    except (OSError, NotImplementedError):
        return False
