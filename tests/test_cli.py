"""명령줄 입력 검사와 실제 실행(더미 데이터 기준) 테스트."""
from __future__ import annotations

import csv
from pathlib import Path
from typing import List

import pytest

import main as cli
from forensic_analyzer.dummy_test import generate


def _run(argv: List[str]) -> None:
    cli.main(argv)


def _read(path: Path) -> List[dict]:
    with open(path, encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


@pytest.fixture(scope="module")
def data(tmp_path_factory) -> Path:
    root = tmp_path_factory.mktemp("case") / "ForensicTestData"
    generate(root)
    return root


@pytest.mark.parametrize("argv", [
    ["inventory", "/no/such/dir"],
    ["inventory", ".", "--with-hash", "--hash-algorithms", "shake_128"],
    ["inventory", ".", "--with-hash", "--hash-algorithms", "sha999"],
    ["inventory", ".", "--with-hash", "--hash-block-size", "0"],
    ["search", "."],
    ["search", ".", "--kw", "(", "--regex"],
    ["search", ".", "--kw", "a", "--encodings", "no-such-enc"],
    ["search", ".", "--kw", "a", "--max-size-mb", "0"],
    ["timeline", ".", "--tz-offset-min", "5000"],
    ["validate", ".", "--baseline", "README.md"],
    ["validate", ".", "--baseline", "no_such.csv"],
])
def test_bad_input_fails_before_scan(argv: List[str], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(Path(cli.__file__).resolve().parent)
    with pytest.raises(SystemExit) as e:
        _run(argv)
    assert e.value.code == 2


def test_uppercase_algorithm_is_normalized(data: Path, tmp_path: Path) -> None:
    out = tmp_path / "inv.csv"
    _run(["inventory", str(data), "--with-hash", "--hash-algorithms", "SHA256", "sha256", "--out", str(out)])
    rows = _read(out)
    assert "sha256" in rows[0] and "SHA256" not in rows[0]


def test_label_is_sanitized_and_outputs_not_overwritten(data: Path, tmp_path: Path) -> None:
    out_dir = tmp_path / "out"
    for _ in range(2):
        _run(["inventory", str(data), "--out-dir", str(out_dir), "--label", "../../escape"])
    files = sorted(p.name for p in out_dir.iterdir())
    assert len(files) == 2 and all("/" not in f for f in files)
    assert not (tmp_path.parent / "escape").exists()


def test_no_hash_columns_when_not_hashed(data: Path, tmp_path: Path) -> None:
    out = tmp_path / "inv.csv"
    _run(["inventory", str(data), "--out", str(out)])
    assert "md5" not in _read(out)[0]


def test_dummy_data_expected_findings(data: Path, tmp_path: Path) -> None:
    out = tmp_path / "inv.csv"
    _run(["inventory", str(data), "--with-signature", "--sig-no-magic", "--out", str(out)])
    flagged = sorted(r["rel_path"] for r in _read(out) if r["ext_mismatch"] == "True")
    assert flagged == ["docs/meeting_notes.txt", "docs/secret.txt", "images/mismatch_signature.jpg"]

    hits = tmp_path / "hits.csv"
    _run(["search", str(data), "--kw", "error", "--kw", "비밀번호", "--out-hits", str(hits)])
    found = sorted((Path(r["path"]).name, r["encoding"]) for r in _read(hits))
    assert found == [("app.log", "utf-8"), ("memo_cp949.txt", "cp949"), ("memo_utf16.txt", "utf-16")]


def test_baseline_roundtrip_via_cli(data: Path, tmp_path: Path) -> None:
    base = tmp_path / "baseline.csv"
    issues = tmp_path / "issues.csv"
    _run(["inventory", str(data), "--with-hash", "--out", str(base)])
    _run(["validate", str(data), "--baseline", str(base), "--out-issues", str(issues)])
    assert _read(issues) == []
