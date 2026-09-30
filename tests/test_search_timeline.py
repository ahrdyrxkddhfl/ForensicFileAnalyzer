"""검색(인코딩, 건너뛴 파일, 다중 일치)과 타임라인 테스트."""
from __future__ import annotations

import os
import random
from pathlib import Path

import pytest

from conftest import can_symlink
from forensic_analyzer.search import search_texts
from forensic_analyzer.timeline import build_timeline_rows, resolve_tzinfo


def test_encodings(write, tmp_path: Path) -> None:
    write("u8.txt", "비밀번호 A\n".encode("utf-8"))
    write("cp.txt", "비밀번호 B\n".encode("cp949"))
    write("u16.txt", "비밀번호 C\n".encode("utf-16"))
    write("u16nobom.txt", "비밀번호 D\n".encode("utf-16-le") * 5)
    write("u16nobom_noascii.txt", "메모비밀번호확인".encode("utf-16-le") * 10)
    hits = search_texts(tmp_path, ["비밀번호"])
    by_file = {Path(h["path"]).name: h["encoding"] for h in hits}
    assert by_file == {"u8.txt": "utf-8", "cp.txt": "cp949", "u16.txt": "utf-16", "u16nobom.txt": "utf-16-le",
                       "u16nobom_noascii.txt": "utf-16-le"}


def test_japanese_found_by_default_like_signature(write, tmp_path: Path) -> None:
    """시그니처가 텍스트로 인정하는 인코딩(Shift-JIS)은 검색 기본값으로도 찾아야 한다."""
    write("jp.txt", "パスワード変更\n".encode("shift_jis") * 20)
    hits = search_texts(tmp_path, ["パスワード"])
    assert len(hits) == 20 and hits[0]["encoding"] == "shift_jis"


def test_gbk_needs_explicit_encoding(write, tmp_path: Path) -> None:
    """GBK는 CP949로도 디코딩되어 자동 구분이 안 되므로, 지정하면 찾을 수 있어야 한다."""
    write("zh.txt", "密码修改请求\n".encode("gbk") * 20)
    assert search_texts(tmp_path, ["密码"], encodings=("utf-8", "gbk"))


@pytest.mark.parametrize("encoding", ["utf-16", "utf-8-sig", "utf-16-le", "utf-8"])
def test_truncated_file_does_not_crash(write, tmp_path: Path, encoding: str) -> None:
    """끝이 잘린 파일 하나 때문에 검색 전체가 멈추면 안 된다."""
    write("cut.txt", ("비밀번호 확인\n" * 20).encode(encoding)[:-1])
    write("ok.txt", "비밀번호 정상\n".encode("utf-8"))
    hits = search_texts(tmp_path, ["비밀번호"])
    assert {Path(h["path"]).name for h in hits} == {"cut.txt", "ok.txt"}


def test_partially_broken_file_is_still_searched(write, tmp_path: Path, rng: random.Random) -> None:
    write("notes.txt", ("안건 검토\n" * 100).encode() + rng.randbytes(5000))
    hits = search_texts(tmp_path, ["안건"])
    assert len(hits) == 100 and hits[0]["encoding"].endswith("+replace")


def test_cp949_file_with_binary_tail(write, tmp_path: Path, rng: random.Random) -> None:
    write("memo.txt", ("안건 검토\n" * 100).encode("cp949") + rng.randbytes(5000))
    hits = search_texts(tmp_path, ["안건"])
    assert len(hits) == 100 and hits[0]["encoding"] == "cp949+replace"


def test_ascii_keyword_in_mostly_binary(write, tmp_path: Path, rng: random.Random) -> None:
    write("dump.log", rng.randbytes(5000) + b"\nERROR here\n" + rng.randbytes(100))
    assert len(search_texts(tmp_path, ["ERROR"], case_sensitive=True)) == 1


def test_ascii_log_with_one_bad_byte(write, tmp_path: Path) -> None:
    """영문 로그에 깨진 바이트 하나가 섞여도 UTF-16으로 잘못 읽지 않고 검색돼야 한다."""
    write("app.log", b"user login failed password reset requested\n" * 50 + b"\xff\n")
    hits = search_texts(tmp_path, ["password"])
    assert len(hits) == 50 and hits[0]["encoding"] == "utf-8+replace"


def test_multiple_matches_in_one_line(write, tmp_path: Path) -> None:
    write("a.log", b"error error ERROR\n")
    assert len(search_texts(tmp_path, ["error"])) == 3
    assert len(search_texts(tmp_path, ["^"], use_regex=True)) == 0  # 빈 일치는 제외


def test_skipped_files_are_recorded(write, tmp_path: Path) -> None:
    write("big.txt", b"a" * 2048)
    write("small.txt", b"needle\n")
    if can_symlink(tmp_path):
        os.symlink("small.txt", tmp_path / "link.txt")
    skipped: list = []
    hits = search_texts(tmp_path, ["needle"], max_file_size_bytes=1024, skipped=skipped)
    assert len(hits) == 1
    reasons = {Path(s["path"]).name: s["reason"] for s in skipped}
    assert reasons["big.txt"] == "too_large"
    if can_symlink(tmp_path):
        assert reasons["link.txt"] == "symlink"


def test_timeline_keeps_suspicious_epochs() -> None:
    rows = [{"path": "a", "mtime_epoch": 0.0, "atime_epoch": 100.0, "ctime_epoch": "", "birthtime_epoch": None}]
    tl = build_timeline_rows(rows, tz_offset_minutes=0)
    assert [(r["event"], r["ts_suspicious"]) for r in tl] == [("Modified", True), ("Accessed", False)]
    assert tl[0]["ts_iso"] == "1970-01-01T00:00:00+00:00"


def test_timeline_marks_future() -> None:
    import time
    tl = build_timeline_rows([{"path": "a", "mtime_epoch": time.time() + 10 * 86400}], tz_offset_minutes=0)
    assert tl[0]["ts_suspicious"] is True


def test_timeline_bad_values_and_tz() -> None:
    rows = [{"path": "a", "mtime_epoch": "nan", "atime_epoch": "abc", "ctime_epoch": 1e20}]
    tl = build_timeline_rows(rows, tz_offset_minutes=540)
    assert len(tl) == 1 and tl[0]["ts_iso"] == ""   # 표현할 수 없는 시각은 빈 문자열
    with pytest.raises(ValueError):
        resolve_tzinfo(1440)
