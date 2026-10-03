"""앱 행동 전후 수집본 비교 테스트."""
from __future__ import annotations

import hashlib
import plistlib
import shutil
import sqlite3
from pathlib import Path
from typing import Dict, List, Tuple

import pytest

from forensic_analyzer.artifactdiff import diff_snapshots

PREFS = """<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
{}
</map>
"""


def _db_with_wal(dest: Path, statements: List[str]) -> None:
    """앱이 실행 중일 때처럼, 마지막 변경이 ``-wal``에만 있는 DB를 ``dest``에 만든다."""
    work = dest.parent / ("_work_" + dest.name)
    con = sqlite3.connect(str(work))
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA wal_autocheckpoint=0")       # WAL을 본 파일에 합치지 않음
    for sql in statements:
        con.execute(sql)
    con.commit()
    shutil.copy2(work, dest)                          # 연결이 열린 상태로 복사(닫으면 WAL이 합쳐짐)
    shutil.copy2(str(work) + "-wal", str(dest) + "-wal")
    con.close()
    for p in work.parent.glob("_work_*"):
        p.unlink()


def _make(root: Path, notes: List[Tuple[int, str]], prefs: str, files: Dict[str, bytes]) -> Path:
    (root / "databases").mkdir(parents=True)
    (root / "shared_prefs").mkdir()
    stmts = ["CREATE TABLE notes (id INTEGER PRIMARY KEY, title TEXT, body BLOB)",
             "CREATE TABLE tags (name TEXT PRIMARY KEY, color INTEGER) WITHOUT ROWID",
             "INSERT INTO tags VALUES ('work', 1)"]
    stmts += [f"INSERT INTO notes VALUES ({i}, '{t}', x'00ff')" for i, t in notes]
    _db_with_wal(root / "databases" / "notes.db", stmts)
    (root / "shared_prefs" / "settings.xml").write_text(PREFS.format(prefs), encoding="utf-8")
    for rel, data in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_bytes(data)
    return root


def _digest(root: Path) -> Dict[str, str]:
    return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(root.rglob("*")) if p.is_file()}


@pytest.fixture
def snapshots(tmp_path: Path) -> Tuple[Path, Path]:
    before = _make(tmp_path / "before", [(1, "장보기")], '<int name="launch_count" value="1" />',
                   {"files/old.txt": b"old", "files/same.txt": b"same"})
    after = _make(tmp_path / "after", [(1, "장보기 목록"), (2, "회의 메모")],
                  '<int name="launch_count" value="2" />\n<boolean name="dark_mode" value="true" />',
                  {"files/new.txt": b"new", "files/same.txt": b"same"})
    return before, after


def _find(rows: List[dict], **kw) -> List[dict]:
    return [r for r in rows if all(r[k] == v for k, v in kw.items())]


def test_rows_in_wal_are_seen(snapshots: Tuple[Path, Path], tmp_path: Path) -> None:
    """방금 쓴 메모(아직 -wal에만 있음)가 행 추가로 보여야 한다."""
    before, after = snapshots
    main_only = tmp_path / "main_only.db"           # 본 파일만 떼어 열면 테이블조차 없다
    shutil.copy2(after / "databases" / "notes.db", main_only)
    assert sqlite3.connect(str(main_only)).execute("SELECT count(*) FROM sqlite_master").fetchone()[0] == 0
    rows = diff_snapshots(before, after)
    added = _find(rows, change="ROW_ADDED", scope="notes")
    assert [(r["key"], "title=회의 메모" in r["after"]) for r in added] == [("rowid=2", True)]
    changed = _find(rows, change="ROW_CHANGED", scope="notes")
    assert [(r["key"], r["column"], r["before"], r["after"]) for r in changed] == [
        ("rowid=1", "title", "장보기", "장보기 목록")]


def test_original_evidence_is_not_modified(snapshots: Tuple[Path, Path]) -> None:
    """비교 후에도 원본 폴더는 바이트 단위로 같고, -shm 같은 새 파일도 생기지 않아야 한다."""
    before, after = snapshots
    expected = (_digest(before), _digest(after))
    diff_snapshots(before, after)
    assert (_digest(before), _digest(after)) == expected


def test_file_and_prefs_changes(snapshots: Tuple[Path, Path]) -> None:
    before, after = snapshots
    rows = diff_snapshots(before, after)
    files = {(r["rel_path"], r["change"]) for r in rows if r["change"].startswith("FILE_")}
    assert ("files/new.txt", "FILE_ADDED") in files and ("files/old.txt", "FILE_DELETED") in files
    assert not any(r["rel_path"] == "files/same.txt" for r in rows)
    prefs = {(r["change"], r["key"], r["before"], r["after"])
             for r in _find(rows, artifact="shared_prefs") if r["change"].startswith("KEY_")}
    assert prefs == {("KEY_CHANGED", "launch_count", "int:1", "int:2"), ("KEY_ADDED", "dark_mode", "", "boolean:true")}
    assert not _find(rows, scope="tags")     # 바뀌지 않은 WITHOUT ROWID 테이블


def test_without_rowid_table_and_deleted_row(tmp_path: Path) -> None:
    def db(root: Path, stmts: List[str]) -> Path:
        root.mkdir()
        con = sqlite3.connect(str(root / "app.sqlite"))
        con.executescript(";".join(["CREATE TABLE kv (k TEXT PRIMARY KEY, v TEXT) WITHOUT ROWID", *stmts]))
        con.close()
        return root
    b = db(tmp_path / "b", ["INSERT INTO kv VALUES ('a', '1')", "INSERT INTO kv VALUES ('b', '2')"])
    a = db(tmp_path / "a", ["INSERT INTO kv VALUES ('a', '9')"])
    rows = _find(diff_snapshots(b, a), artifact="sqlite")
    got = {(r["change"], r["key"], r["column"]) for r in rows if r["change"].startswith("ROW_")}
    assert got == {("ROW_CHANGED", "a", "v"), ("ROW_DELETED", "b", "")}


def test_only_wal_changed(tmp_path: Path) -> None:
    """본 DB 파일은 그대로이고 -wal만 바뀐 경우도 내용 변화를 보여 준다."""
    stmts = ["CREATE TABLE t (x)", "INSERT INTO t VALUES (1)"]
    b, a = tmp_path / "b", tmp_path / "a"
    b.mkdir(), a.mkdir()
    con = sqlite3.connect(str(b / "x.db"))
    con.executescript(";".join(stmts))
    con.close()
    shutil.copy2(b / "x.db", a / "x.db")
    work = tmp_path / "w.db"
    shutil.copy2(b / "x.db", work)
    con = sqlite3.connect(str(work))
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA wal_autocheckpoint=0")
    con.execute("INSERT INTO t VALUES (2)")
    con.commit()
    shutil.copy2(str(work) + "-wal", a / "x.db-wal")
    con.close()
    rows = diff_snapshots(b, a)
    assert {(r["rel_path"], r["change"]) for r in rows} == {("x.db-wal", "FILE_ADDED"), ("x.db", "ROW_ADDED")}



def test_unreadable_table_does_not_hide_other_tables(tmp_path: Path) -> None:
    """이 환경에 없는 모듈을 쓰는 가상 테이블 하나 때문에 DB 전체 비교를 포기하면 안 된다."""
    for side, n in (("b", 1), ("a", 2)):
        (tmp_path / side).mkdir()
        con = sqlite3.connect(str(tmp_path / side / "x.db"))
        con.execute("CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT)")
        con.executemany("INSERT INTO notes (body) VALUES (?)", [(f"n{i}",) for i in range(n)])
        con.execute("PRAGMA writable_schema=ON")
        con.execute("INSERT INTO sqlite_master VALUES "
                    "('table','search','search',0,'CREATE VIRTUAL TABLE search USING nosuchmodule(body)')")
        con.commit()
        con.close()
    rows = diff_snapshots(tmp_path / "b", tmp_path / "a")
    assert {(r["change"], r["scope"]) for r in rows if not r["change"].startswith("FILE_")} == {
        ("PARSE_ERROR", "search"), ("ROW_ADDED", "notes")}


def test_column_named_rowid_does_not_merge_rows(tmp_path: Path) -> None:
    """사용자 열 이름이 rowid여도 실제 rowid로 짝지어야 한다(같은 값의 행이 합쳐지면 안 됨)."""
    for side, rows in (("b", [("same", "1"), ("same", "2")]), ("a", [("same", "1"), ("same", "9")])):
        (tmp_path / side).mkdir()
        con = sqlite3.connect(str(tmp_path / side / "y.db"))
        con.execute("CREATE TABLE t (rowid TEXT, v TEXT)")
        con.executemany("INSERT INTO t VALUES (?, ?)", rows)
        con.commit()
        con.close()
    got = [(r["change"], r["key"], r["column"], r["before"], r["after"])
           for r in diff_snapshots(tmp_path / "b", tmp_path / "a") if r["change"].startswith("ROW_")]
    assert got == [("ROW_CHANGED", "rowid=2", "v", "2", "9")]


def test_table_without_any_key(tmp_path: Path) -> None:
    """rowid 별칭이 모두 열 이름으로 가려지고 기본 키도 없으면, 행 내용으로 짝짓는다."""
    for side, rows in (("b", [(1, 1, 1), (1, 1, 1)]), ("a", [(1, 1, 1)])):
        (tmp_path / side).mkdir()
        con = sqlite3.connect(str(tmp_path / side / "z.db"))
        con.execute("CREATE TABLE t (rowid, _rowid_, oid)")
        con.executemany("INSERT INTO t VALUES (?, ?, ?)", rows)
        con.commit()
        con.close()
    got = [(r["change"], r["key"]) for r in diff_snapshots(tmp_path / "b", tmp_path / "a")
           if r["change"].startswith("ROW_")]
    assert got == [("ROW_DELETED", "1, 1, 1, #2")]   # 같은 행 두 개 중 하나가 사라짐

def test_plist_and_broken_files(tmp_path: Path) -> None:
    b, a = tmp_path / "b", tmp_path / "a"
    for root, plist, db in ((b, {"user": {"name": "kim"}, "ids": [1]}, b"SQLite format 3\x00" + bytes(100)),
                            (a, {"user": {"name": "lee"}, "ids": [1, 2]}, b"SQLite format 3\x00" + bytes(99) + b"!")):
        root.mkdir()
        (root / "prefs.plist").write_bytes(plistlib.dumps(plist, fmt=plistlib.FMT_BINARY))
        (root / "broken.db").write_bytes(db)
        (root / "conf.xml").write_text("<?xml version='1.0'?>\n<map><string name='k'>", encoding="utf-8")
    (a / "conf.xml").write_text("<?xml version='1.0'?>\n<map><string name='k'>x", encoding="utf-8")
    rows = diff_snapshots(b, a)
    plist = {(r["change"], r["key"], r["after"]) for r in _find(rows, artifact="plist") if r["change"] != "FILE_MODIFIED"}
    assert plist == {("KEY_CHANGED", "user.name", "lee"), ("KEY_ADDED", "ids[1]", "2")}
    assert _find(rows, rel_path="broken.db", change="PARSE_ERROR")       # 깨진 DB에서 멈추지 않음
    assert _find(rows, rel_path="conf.xml", change="PARSE_ERROR")        # 깨진 설정 XML


def test_cli_appdiff(snapshots: Tuple[Path, Path], tmp_path: Path) -> None:
    import csv
    import main as cli
    before, after = snapshots
    out = tmp_path / "diff.csv"
    cli.main(["appdiff", str(after), "--before", str(before), "--out-diff", str(out)])
    with open(out, encoding="utf-8-sig", newline="") as f:
        assert any(r["change"] == "ROW_ADDED" for r in csv.DictReader(f))
    with pytest.raises(SystemExit):
        cli.main(["appdiff", str(after), "--before", str(tmp_path / "nope")])


SAMPLES = Path(__file__).resolve().parent.parent / "samples" / "fossify_notes"


@pytest.mark.parametrize("before,after,expected", [
    ("s1_first_launch", "s2_note_created",
     {("ROW_ADDED", "notes", "rowid=2", ""), ("ROW_CHANGED", "sqlite_sequence", "rowid=1", "seq")}),
    ("s2_note_created", "s3_note_edited", {("ROW_CHANGED", "notes", "rowid=2", "value")}),
    ("s3_note_edited", "s4_note_deleted", {("ROW_DELETED", "notes", "rowid=2", "")}),
    ("s4_note_deleted", "s5_note_locked",
     {("ROW_CHANGED", "notes", "rowid=1", "protection_hash"), ("ROW_CHANGED", "notes", "rowid=1", "protection_type")}),
    ("s5_note_locked", "s6_secret_locked",
     {("ROW_ADDED", "notes", "rowid=3", ""), ("ROW_CHANGED", "sqlite_sequence", "rowid=1", "seq")}),
])
def test_real_app_snapshots(before: str, after: str, expected: set) -> None:
    """실제 앱(Fossify Notes) 수집본: 행동마다 기대한 행 변화만 나오고, 수집본은 그대로여야 한다."""
    roots = (SAMPLES / before, SAMPLES / after)
    digests = tuple(_digest(r) for r in roots)
    rows = diff_snapshots(*roots)
    assert {(r["change"], r["scope"], r["key"], r["column"]) for r in rows if r["change"].startswith("ROW_")} == expected
    assert not any(r["rel_path"].endswith("databases/notes.db") and r["change"].startswith("FILE_") for r in rows)
    assert tuple(_digest(r) for r in roots) == digests


def test_real_app_content_lives_only_in_wal(tmp_path: Path) -> None:
    """실제 앱 DB는 본 파일만 열면 메모 테이블조차 없다(내용이 전부 -wal에 있음)."""
    main_only = tmp_path / "notes.db"
    shutil.copy2(SAMPLES / "s6_secret_locked" / "org.fossify.notes" / "databases" / "notes.db", main_only)
    assert sqlite3.connect(str(main_only)).execute("SELECT count(*) FROM sqlite_master").fetchone()[0] == 0
