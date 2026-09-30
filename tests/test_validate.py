"""기준본 비교와 인벤토리 검증 테스트. 2차·3차 검토에서 재현한 사례를 모두 포함한다."""
from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Dict, List

import pytest

from forensic_analyzer.foroutput import write_rows_csv
from forensic_analyzer.hashing import add_hashes_to_rows
from forensic_analyzer.inventory import collect_inventory
from forensic_analyzer.validate import compare_with_baseline, load_inventory_csv, validate_inventory_rows


def _save(rows: List[Dict[str, object]], path: Path) -> List[Dict[str, str]]:
    """행을 CSV로 저장했다가 다시 읽는다(실제 기준본과 같은 경로를 거치게)."""
    write_rows_csv(rows, path)
    return load_inventory_csv(path)


def _inv(root: Path, hashed: bool = True, algos=("md5", "sha256")) -> List[Dict[str, object]]:
    rows = collect_inventory(root)
    if hashed:
        add_hashes_to_rows(rows, algorithms=algos)
    return rows


def _codes(issues) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    for i in issues:
        out.setdefault(i.code, []).append(i.detail)
    return out


@pytest.fixture
def case(tmp_path: Path, write) -> Path:
    root = tmp_path / "case"
    for rel, data in {"docs/notes.txt": b"one two three\n", "docs/table.csv": b"a,b\n1,2\n",
                      "img/photo.png": b"\x89PNG\r\n\x1a\n" + b"x" * 100, "e1.bin": b"", "keep.log": b"log\n"}.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    return root


def test_no_change(case: Path, tmp_path: Path) -> None:
    base = _save(_inv(case), tmp_path / "b.csv")
    assert compare_with_baseline(_inv(case), base) == []


def test_tamper_same_size_and_restored_mtime(case: Path, tmp_path: Path) -> None:
    base = _save(_inv(case), tmp_path / "b.csv")
    p = case / "docs" / "notes.txt"
    st = p.stat()
    p.write_bytes(b"ONE two three\n")          # 같은 크기
    os.utime(p, (st.st_atime, st.st_mtime))   # 수정 시각 되돌리기(touch -r)
    codes = _codes(compare_with_baseline(_inv(case), base))
    assert set(codes) == {"HASH_CHANGED"}


def test_baseline_without_hash_values_warns(case: Path, tmp_path: Path) -> None:
    """해시 없이 만든 기준본: 열이 없으니 값 기준으로 판단해 BASELINE_NO_HASH(WARN)를 내야 한다."""
    base = _save(_inv(case, hashed=False), tmp_path / "b.csv")
    issues = compare_with_baseline(_inv(case), base)
    no_hash = [i for i in issues if i.code == "BASELINE_NO_HASH"]
    assert len(no_hash) == 1 and no_hash[0].severity == "WARN"
    assert not any(i.code == "HASH_NOT_COMPARED" for i in issues)


def test_baseline_with_empty_hash_columns_warns(case: Path, tmp_path: Path) -> None:
    """(구버전 도구처럼) 해시 열은 있는데 값이 전부 비어 있어도 '해시 있음'으로 보면 안 된다."""
    rows = _inv(case, hashed=False)
    for r in rows:
        r["md5"], r["sha256"] = "", ""
    base = _save(rows, tmp_path / "b.csv")
    assert any(i.code == "BASELINE_NO_HASH" for i in compare_with_baseline(_inv(case), base))


def test_different_algorithm_warns(case: Path, tmp_path: Path) -> None:
    base = _save(_inv(case, algos=("md5", "sha256")), tmp_path / "b.csv")
    issues = compare_with_baseline(_inv(case, algos=("sha1",)), base, algorithms=("sha1",))
    assert any(i.code == "BASELINE_NO_HASH" for i in issues)


def test_move_detection_is_conservative(case: Path, tmp_path: Path) -> None:
    base = _save(_inv(case), tmp_path / "b.csv")
    shutil.move(str(case / "docs" / "notes.txt"), str(case / "moved_notes.txt"))  # 이동
    (case / "e1.bin").unlink()                                                     # 빈 파일 삭제
    (case / "other_empty.log").write_bytes(b"")                                    # 다른 빈 파일 추가
    codes = _codes(compare_with_baseline(_inv(case), base))
    assert len(codes["MOVED"]) == 1 and "notes.txt" in codes["MOVED"][0]
    assert any("e1.bin" in d for d in codes["BASELINE_MISSING"])       # 빈 파일 삭제는 이동으로 묻히지 않음
    assert any("other_empty.log" in d for d in codes["BASELINE_NEW"])


def test_duplicate_contents_are_not_paired(case: Path, tmp_path: Path) -> None:
    (case / "a.txt").write_bytes(b"same")
    (case / "b.txt").write_bytes(b"same")
    base = _save(_inv(case), tmp_path / "b.csv")
    (case / "a.txt").unlink()
    (case / "b.txt").unlink()
    (case / "c.txt").write_bytes(b"same")
    (case / "d.txt").write_bytes(b"same")
    codes = _codes(compare_with_baseline(_inv(case), base))
    assert "MOVED" not in codes and len(codes["BASELINE_MISSING"]) == 2


def test_folder_relocation_uses_rel_path(case: Path, tmp_path: Path) -> None:
    base = _save(_inv(case), tmp_path / "b.csv")
    moved = tmp_path / "elsewhere"
    shutil.copytree(case, moved, copy_function=shutil.copy2)
    assert compare_with_baseline(_inv(moved), base) == []


@pytest.mark.parametrize("content", [b"# README\nhello\n", b"a,b\n1,2\n", b"\x89PNG\r\n\x1a\n\x00\xff"])
def test_bad_baseline_file_is_rejected(tmp_path: Path, content: bytes) -> None:
    p = tmp_path / "bad.csv"
    p.write_bytes(content)
    with pytest.raises(ValueError):
        load_inventory_csv(p)


def test_nfd_filenames_match_nfc_baseline(tmp_path: Path) -> None:
    """macOS 자모 분리형(NFD) 파일명과 NFC 기준본이 같은 파일로 짝지어져야 한다."""
    import unicodedata
    root = tmp_path / "c"
    root.mkdir()
    (root / "증거.txt").write_bytes(b"x")
    rows = _inv(root)
    base = _save(rows, tmp_path / "b.csv")
    for r in rows:
        r["rel_path"] = unicodedata.normalize("NFD", str(r["rel_path"]))
    assert compare_with_baseline(rows, base) == []


def test_formula_like_filenames_roundtrip(tmp_path: Path) -> None:
    """수식처럼 보이는 파일명은 CSV에서 무력화되고, 기준본으로 읽을 때 원래 이름으로 돌아와야 한다."""
    root = tmp_path / "c"
    root.mkdir()
    (root / "=HYPERLINK(1).txt").write_bytes(b"x")
    (root / "-note.txt").write_bytes(b"y")
    rows = _inv(root)
    csv_path = tmp_path / "b.csv"
    write_rows_csv(rows, csv_path)
    raw = csv_path.read_text(encoding="utf-8-sig")
    assert "'=HYPERLINK" in raw and "'-note" in raw
    base = load_inventory_csv(csv_path)
    assert {r["name"] for r in base} == {"=HYPERLINK(1).txt", "-note.txt"}
    assert compare_with_baseline(_inv(root), base) == []


def test_inventory_validation_codes(case: Path) -> None:
    import time
    rows = _inv(case)
    rows[4]["atime_epoch"] = time.time() + 10 * 86400
    rows[0]["mtime_epoch"] = 0.0
    rows[1]["hash_status"] = "read_error"
    rows[2]["hash_status"] = "changed_during_hash"
    rows[3]["sig_source"] = "error"
    rows.append(dict(rows[4]))
    codes = _codes(validate_inventory_rows(rows, hash_algorithms=("sha256",)))
    for code in ("TS_SUSPICIOUS", "TS_FUTURE", "HASH_READ_FAIL", "CHANGED_DURING_HASH", "SIGNATURE_READ_FAIL", "DUP_PATH"):
        assert code in codes, code
