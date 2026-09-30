"""인벤토리 수집(심볼릭 링크 정책, 순환 방지, 플랫폼 시간)과 해시 테스트."""
from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from conftest import can_symlink
from forensic_analyzer.hashing import add_hashes_to_rows, compute_file_hashes
from forensic_analyzer.inventory import collect_inventory, is_excluded, platform_times


def test_rows_are_sorted_and_relative(write, tmp_path: Path) -> None:
    write("b/2.txt", b"2")
    write("a/1.txt", b"1")
    rows = collect_inventory(tmp_path)
    assert [r["rel_path"] for r in rows] == ["a/1.txt", "b/2.txt"]


def test_exclude_uses_posix_paths() -> None:
    assert is_excluded(Path("/case/.git/config"), ("*/.git/*",))
    assert is_excluded(Path("C:/case/.git/config"), ("*/.git/*",))


def test_symlink_recorded_as_link_by_default(write, tmp_path: Path) -> None:
    if not can_symlink(tmp_path):
        pytest.skip("심볼릭 링크를 만들 수 없는 환경")
    write("docs/r.txt", b"report")
    (tmp_path / "links").mkdir()
    os.symlink(os.path.join("..", "docs", "r.txt"), tmp_path / "links" / "l.txt")
    rows = {r["rel_path"]: r for r in collect_inventory(tmp_path)}
    link = rows["links/l.txt"]
    assert link["is_symlink"] is True
    assert link["link_target"] == os.path.join("..", "docs", "r.txt")

    add_hashes_to_rows(list(rows.values()))
    assert link["hash_status"] == "symlink_skipped" and link["sha256"] == ""
    assert link["link_broken"] is False

    os.symlink("nowhere.txt", tmp_path / "links" / "dead.txt")
    dead = [r for r in collect_inventory(tmp_path) if r["rel_path"] == "links/dead.txt"][0]
    assert dead["link_broken"] is True   # 따라가지 않는 모드에서도 깨진 링크를 표시


def test_follow_mode_blocks_cycles_and_records_broken(write, tmp_path: Path) -> None:
    if not can_symlink(tmp_path):
        pytest.skip("심볼릭 링크를 만들 수 없는 환경")
    for i in range(4):
        write(f"d/f{i}.txt", b"x")
    os.symlink("..", tmp_path / "d" / "loop")          # 상위 폴더를 가리키는 순환 링크
    os.symlink("nowhere.txt", tmp_path / "broken.txt")  # 깨진 링크
    errors: list = []
    rows = collect_inventory(tmp_path, follow_symlinks=True, errors=errors)
    names = [r["rel_path"] for r in rows]
    assert len([n for n in names if n.endswith(".txt") and "f" in Path(n).name]) == 4
    assert any("순환" in e["reason"] for e in errors)
    broken = [r for r in rows if r["rel_path"] == "broken.txt"][0]
    assert broken["link_broken"] is True


def test_unreadable_directory_is_recorded(write, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    write("ok/a.txt", b"a")
    write("locked/b.txt", b"b")
    real_scandir = os.scandir

    def fake_scandir(path):
        if Path(path).name == "locked":
            raise PermissionError("denied")
        return real_scandir(path)

    monkeypatch.setattr(os, "scandir", fake_scandir)
    errors: list = []
    rows = collect_inventory(tmp_path, errors=errors)
    assert [r["rel_path"] for r in rows] == ["ok/a.txt"]
    assert errors and "locked" in errors[0]["path"]


def test_platform_times() -> None:
    win = SimpleNamespace(st_ctime=100.0)
    assert platform_times(win, is_windows=True) == (100.0, None)                 # ctime = 생성
    win312 = SimpleNamespace(st_ctime=100.0, st_birthtime=90.0)
    assert platform_times(win312, is_windows=True) == (90.0, None)
    mac = SimpleNamespace(st_ctime=200.0, st_birthtime=50.0)
    assert platform_times(mac, is_windows=False) == (50.0, 200.0)               # ctime = 메타데이터 변경
    linux = SimpleNamespace(st_ctime=200.0)
    assert platform_times(linux, is_windows=False) == (None, 200.0)


def test_hash_values_and_bad_chunk(write) -> None:
    p = write("a.txt", b"abc")
    assert compute_file_hashes(p, ("md5", "sha256")) == {
        "md5": "900150983cd24fb0d6963f7d28e17f72",
        "sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    }
    with pytest.raises(ValueError):
        compute_file_hashes(p, ("md5",), chunk_size=0)


def test_hash_read_error_and_change_during_hash(write, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    write("a.txt", b"aaa")
    write("b.txt", b"bbb")
    rows = collect_inventory(tmp_path)
    import forensic_analyzer.hashing as H
    real = H.compute_file_hashes

    def fake(path, algorithms, *, chunk_size):
        if str(path).endswith("a.txt"):
            return None                                   # 읽기 실패 흉내
        Path(path).write_bytes(b"bbbb")                   # 해시 도중 파일이 바뀜 흉내
        return real(path, algorithms, chunk_size=chunk_size)

    monkeypatch.setattr(H, "compute_file_hashes", fake)
    add_hashes_to_rows(rows, algorithms=("sha256",))
    status = {r["rel_path"]: r["hash_status"] for r in rows}
    assert status == {"a.txt": "read_error", "b.txt": "changed_during_hash"}
