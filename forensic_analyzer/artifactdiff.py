# forensic_analyzer/artifactdiff.py
"""앱 행동 전후의 데이터 폴더를 비교해, 어떤 파일의 어느 부분이 바뀌었는지 찾는다.

앱에서 메모 작성 같은 행동을 하기 전과 후에 앱 데이터 폴더를 각각 수집해 두고 비교하면,
"이 행동을 하면 이 파일의 이 부분이 생기거나 바뀐다"는 아티팩트 명세를 만들 수 있다.

비교 단위:
    1. 파일: ``rel_path``로 짝지어 추가·삭제·변경(SHA-256)을 찾는다.
    2. 내용: 바뀐 파일 중 형식을 아는 것은 안을 열어 비교한다. 형식은 확장자가 아니라
       앞부분 바이트로 판별한다.

       - SQLite DB: 테이블별로 행 추가·삭제·변경. 행은 rowid(없으면 기본 키)로 짝짓고,
         변경은 열 단위로 기록한다.
       - 설정 XML(안드로이드 ``shared_prefs``의 ``<map>``): 키 추가·삭제·변경
       - plist(XML·바이너리): 중첩된 키를 ``a.b[0]`` 형태 경로로 펼쳐 키 단위로 비교

SQLite WAL:
    안드로이드 앱 DB는 대부분 WAL 모드라, 최근 변경이 본 DB 파일이 아니라 ``-wal`` 파일에
    먼저 쌓인다. 본 DB 파일만 읽으면 방금 쓴 메모가 보이지 않는다. 그래서 DB와 ``-wal``을
    임시 폴더에 복사해 WAL까지 반영된 상태로 읽는다. 원본(증거)은 열지 않는다. SQLite는
    DB를 열 때 ``-shm``을 만들고 닫을 때 WAL을 본 파일에 합치므로, 원본을 직접 열면 증거가
    바뀌기 때문이다. ``-wal``·``-shm``·``-journal``만 바뀐 경우도 본 DB의 내용 비교로 보여 준다.

Example:
    >>> flatten_plist({"a": {"b": [1, 2]}, "c": True})
    {'a.b[0]': 1, 'a.b[1]': 2, 'c': True}
"""
from __future__ import annotations

import plistlib
import shutil
import sqlite3
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from collections import Counter
from typing import Dict, Iterable, List, Optional, Tuple, Union

from .hashing import add_hashes_to_rows
from .inventory import collect_inventory

DIFF_FIELDS: Tuple[str, ...] = ("rel_path", "artifact", "change", "scope", "key", "column", "before", "after")

ARTIFACT_SQLITE = "sqlite"
ARTIFACT_PREFS = "shared_prefs"
ARTIFACT_PLIST = "plist"
ARTIFACT_FILE = "file"

SQLITE_MAGIC = b"SQLite format 3\x00"
SQLITE_SIDECARS = ("-wal", "-shm", "-journal")

# 결과 한 칸에 담는 값의 최대 길이. 넘으면 앞부분과 원래 길이를 남긴다.
MAX_VALUE_CHARS = 300
# 새로 생긴 테이블처럼 행이 많을 수 있는 경우, 테이블당 기록하는 행 변화 상한.
MAX_ROWS_PER_TABLE = 1000
# 설정 파일·plist를 메모리에 읽는 상한.
MAX_TEXT_ARTIFACT_BYTES = 16 * 1024 * 1024

Value = object
Row = Dict[str, object]
TableRows = Dict[Tuple, Dict[str, Value]]


def diff_snapshots(
    before_root: Union[str, Path],
    after_root: Union[str, Path],
    *,
    exclude_globs: Iterable[str] = (),
    errors: Optional[List[Dict[str, str]]] = None,
) -> List[Row]:
    """두 수집본(행동 전·후 폴더)을 비교한다.

    Args:
        before_root: 행동 전에 수집한 폴더.
        after_root: 행동 후에 수집한 폴더.
        exclude_globs: 제외할 글롭 패턴.
        errors: 읽지 못한 폴더·파일을 기록할 리스트.

    Returns:
        ``DIFF_FIELDS`` 열을 가진 행 리스트. 파일 단위 변화 다음에 그 파일의 내용 변화가 온다.
    """
    before = _snapshot(before_root, exclude_globs, errors)
    after = _snapshot(after_root, exclude_globs, errors)
    out: List[Row] = []

    changed_dbs: Dict[str, None] = {}   # 내용 비교할 SQLite DB(rel_path), 순서 유지
    for rel in sorted(set(before) | set(after)):
        b, a = before.get(rel), after.get(rel)
        if b and a and b["sha256"] == a["sha256"]:
            continue
        path = a["path"] if a else b["path"]
        kind = _artifact_kind(Path(str(path)))
        change = "FILE_ADDED" if not b else "FILE_DELETED" if not a else "FILE_MODIFIED"
        out.append(_row(rel, kind, change, before=_file_summary(b), after=_file_summary(a)))

        db_rel = _sqlite_main(rel)
        if db_rel is not None and (db_rel in before or db_rel in after):
            changed_dbs[db_rel] = None      # -wal 등만 바뀌어도 본 DB 내용을 비교한다
        elif kind == ARTIFACT_SQLITE:
            changed_dbs[rel] = None
        elif kind == ARTIFACT_PREFS:
            out += _diff_keyed(rel, kind, _read_prefs, b, a)
        elif kind == ARTIFACT_PLIST:
            out += _diff_keyed(rel, kind, _read_plist, b, a)

    for rel in changed_dbs:
        b, a = before.get(rel), after.get(rel)
        if (b and _artifact_kind(Path(str(b["path"]))) != ARTIFACT_SQLITE) or \
                (a and _artifact_kind(Path(str(a["path"]))) != ARTIFACT_SQLITE):
            continue   # 이름만 -wal 짝이 맞고 SQLite가 아닌 파일
        out += diff_sqlite(rel, Path(str(b["path"])) if b else None, Path(str(a["path"])) if a else None)
    return out


def diff_sqlite(rel: str, before: Optional[Path], after: Optional[Path]) -> List[Row]:
    """두 SQLite DB의 테이블·행 차이를 구한다(WAL 반영, 원본은 열지 않음).

    Args:
        rel: 결과에 기록할 상대 경로.
        before: 행동 전 DB 경로. 없었으면 None.
        after: 행동 후 DB 경로. 없어졌으면 None.

    Returns:
        ``TABLE_ADDED``/``TABLE_DELETED``/``ROW_ADDED``/``ROW_DELETED``/``ROW_CHANGED`` 행.
        DB를 열 수 없으면 ``PARSE_ERROR`` 한 행. 테이블 하나만 읽지 못하면(예: 이 환경에
        없는 모듈을 쓰는 가상 테이블) 그 테이블만 ``PARSE_ERROR``로 남기고 나머지는 비교한다.
    """
    try:
        tb, errors_b = _read_sqlite(before) if before else ({}, {})
        ta, errors_a = _read_sqlite(after) if after else ({}, {})
    except (sqlite3.Error, OSError) as e:   # 깨진 DB, 사본을 만들지 못함
        return [_row(rel, ARTIFACT_SQLITE, "PARSE_ERROR", after=f"{type(e).__name__}: {e}")]

    out: List[Row] = []
    for table in sorted(set(errors_b) | set(errors_a)):
        out.append(_row(rel, ARTIFACT_SQLITE, "PARSE_ERROR", scope=table,
                        before=errors_b.get(table, ""), after=errors_a.get(table, "")))
    for table in sorted((set(tb) | set(ta)) - set(errors_b) - set(errors_a)):
        rows_b, rows_a = tb.get(table, {}), ta.get(table, {})
        if table not in tb:
            out.append(_row(rel, ARTIFACT_SQLITE, "TABLE_ADDED", scope=table, after=f"{len(rows_a)}행"))
        elif table not in ta:
            out.append(_row(rel, ARTIFACT_SQLITE, "TABLE_DELETED", scope=table, before=f"{len(rows_b)}행"))
        changes: List[Row] = []
        for key in sorted(set(rows_b) | set(rows_a), key=_sort_key):
            rb, ra = rows_b.get(key), rows_a.get(key)
            if rb == ra:
                continue
            k = _key_text(key)
            if rb is None:
                changes.append(_row(rel, ARTIFACT_SQLITE, "ROW_ADDED", scope=table, key=k, after=_row_text(ra)))
            elif ra is None:
                changes.append(_row(rel, ARTIFACT_SQLITE, "ROW_DELETED", scope=table, key=k, before=_row_text(rb)))
            else:
                for col in sorted(set(rb) | set(ra)):
                    if rb.get(col) != ra.get(col):
                        changes.append(_row(rel, ARTIFACT_SQLITE, "ROW_CHANGED", scope=table, key=k, column=col,
                                            before=_value_text(rb.get(col)), after=_value_text(ra.get(col))))
        if len(changes) > MAX_ROWS_PER_TABLE:
            omitted = len(changes) - MAX_ROWS_PER_TABLE
            changes = changes[:MAX_ROWS_PER_TABLE] + [
                _row(rel, ARTIFACT_SQLITE, "TRUNCATED", scope=table, after=f"변화 {omitted}건 더 있음(생략)")]
        out += changes
    return out


def flatten_plist(value: Value, prefix: str = "") -> Dict[str, Value]:
    """중첩된 plist 값을 ``a.b[0]`` 형태의 경로 → 값 사전으로 펼친다.

    Args:
        value: plist 값.
        prefix: 현재 경로.

    Returns:
        펼친 사전. 빈 사전·빈 목록은 그 자체를 값으로 남긴다.
    """
    if isinstance(value, dict) and value:
        out: Dict[str, Value] = {}
        for k, v in value.items():
            out.update(flatten_plist(v, f"{prefix}.{k}" if prefix else str(k)))
        return out
    if isinstance(value, list) and value:
        out = {}
        for i, v in enumerate(value):
            out.update(flatten_plist(v, f"{prefix}[{i}]"))
        return out
    return {prefix: value}


# ---------------------------------------------------------------------------
# 내부 유틸
# ---------------------------------------------------------------------------

def _snapshot(root: Union[str, Path], exclude_globs: Iterable[str],
              errors: Optional[List[Dict[str, str]]]) -> Dict[str, Row]:
    """수집본 폴더의 파일을 ``rel_path`` → 행(SHA-256 포함)으로 모은다(심볼릭 링크 제외).

    Args:
        root: 수집본 폴더.
        exclude_globs: 제외할 글롭 패턴.
        errors: 읽지 못한 항목을 기록할 리스트.

    Returns:
        ``rel_path`` → 인벤토리 행.
    """
    rows = collect_inventory(root, exclude_globs=list(exclude_globs), errors=errors)
    rows = [r for r in rows if not r.get("is_symlink")]
    add_hashes_to_rows(rows, algorithms=("sha256",))
    return {str(r["rel_path"]): r for r in rows}


def _artifact_kind(path: Path) -> str:
    """앞부분 바이트로 비교 방법을 고른다(확장자는 보지 않는다).

    Args:
        path: 파일 경로.

    Returns:
        ``sqlite``/``shared_prefs``/``plist``/``file``.
    """
    try:
        with path.open("rb") as f:
            head = f.read(512)
    except OSError:
        return ARTIFACT_FILE
    if head.startswith(SQLITE_MAGIC):
        return ARTIFACT_SQLITE
    if head.startswith(b"bplist00"):
        return ARTIFACT_PLIST
    text = head.lstrip(b"\xef\xbb\xbf \t\r\n")
    if text.startswith((b"<?xml", b"<plist", b"<map", b"<!DOCTYPE plist")):
        if b"<plist" in head or b"PropertyList" in head:
            return ARTIFACT_PLIST
        if b"<map" in head:
            return ARTIFACT_PREFS
    return ARTIFACT_FILE


def _sqlite_main(rel: str) -> Optional[str]:
    """SQLite 부속 파일(``-wal``·``-shm``·``-journal``)이면 본 DB의 경로를 돌려준다.

    Args:
        rel: 상대 경로.

    Returns:
        본 DB 상대 경로. 부속 파일이 아니면 None.

    Example:
        >>> _sqlite_main("databases/notes.db-wal")
        'databases/notes.db'
    """
    for suffix in SQLITE_SIDECARS:
        if rel.endswith(suffix):
            return rel[: -len(suffix)]
    return None


def _read_sqlite(path: Path) -> Tuple[Dict[str, TableRows], Dict[str, str]]:
    """DB를 임시 사본으로 열어 테이블 → (행 키 → {열: 값})으로 읽는다.

    Args:
        path: 원본 DB 경로. 같은 폴더의 ``-wal``도 함께 복사한다.

    Returns:
        ``(테이블별 행, 읽지 못한 테이블 → 오류)``. 행 키는 ``_read_table`` 참고.
    """
    with tempfile.TemporaryDirectory() as tmp:
        copy = Path(tmp) / path.name
        shutil.copy2(path, copy)
        wal = path.with_name(path.name + "-wal")
        if wal.is_file():
            shutil.copy2(wal, copy.with_name(copy.name + "-wal"))
        con = sqlite3.connect(str(copy))
        try:
            con.text_factory = lambda b: b.decode("utf-8", "replace")
            names = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
            tables: Dict[str, TableRows] = {}
            errors: Dict[str, str] = {}
            for t in names:
                try:
                    tables[t] = _read_table(con, t)
                except sqlite3.Error as e:
                    errors[t] = f"{type(e).__name__}: {e}"
            return tables, errors
        finally:
            con.close()


def _read_table(con: sqlite3.Connection, table: str) -> TableRows:
    """테이블 하나의 모든 행을 행 키 → {열: 값}으로 읽는다.

    행 키는 다음 순서로 정한다.

    1. rowid. 사용자 열 이름이 ``rowid``이면 그 열이 읽히므로, 가려지지 않은 별칭
       (``rowid``·``_rowid_``·``oid``)을 고른다. 키는 ``("rowid", n)``.
    2. WITHOUT ROWID 테이블은 기본 키 값 튜플.
    3. 둘 다 없으면 행 내용과 같은 내용 안에서의 순번(같은 행이 여러 개일 수 있음).

    Args:
        con: DB 연결.
        table: 테이블 이름.

    Returns:
        행 키 → 열 값 사전.

    Raises:
        sqlite3.Error: 테이블을 읽을 수 없을 때(없는 모듈을 쓰는 가상 테이블 등).
    """
    q = '"' + table.replace('"', '""') + '"'
    info = con.execute(f"PRAGMA table_info({q})").fetchall()
    taken = {c[1].lower() for c in info}
    alias = next((a for a in ("rowid", "_rowid_", "oid") if a not in taken), None)
    if alias:
        try:
            cur = con.execute(f"SELECT {alias} AS __ffa_rowid__, * FROM {q}")
            cols = [d[0] for d in cur.description][1:]
            return {("rowid", r[0]): dict(zip(cols, r[1:])) for r in cur}
        except sqlite3.OperationalError:
            pass   # WITHOUT ROWID 테이블
    pk = [c[1] for c in sorted(info, key=lambda c: c[5]) if c[5] > 0]
    cur = con.execute(f"SELECT * FROM {q}")
    cols = [d[0] for d in cur.description]
    rows = [dict(zip(cols, r)) for r in cur]
    if pk:
        return {tuple(r[c] for c in pk): r for r in rows}
    seen: Counter = Counter()
    out: TableRows = {}
    for r in rows:
        content = tuple(_value_text(v) for v in r.values())
        seen[content] += 1
        out[(*content, f"#{seen[content]}")] = r
    return out

def _read_prefs(path: Path) -> Dict[str, Value]:
    """안드로이드 ``shared_prefs`` XML을 키 → ``타입:값``으로 읽는다.

    Args:
        path: XML 경로.

    Returns:
        키 → 값 문자열(타입 포함, 예: ``boolean:true``).
    """
    root = ET.fromstring(_read_limited(path))
    out: Dict[str, Value] = {}
    for el in root:
        name = el.get("name")
        if name is None:
            continue
        if el.tag == "string":
            value = el.text or ""
        elif el.tag == "set":
            value = "{" + ", ".join(sorted(c.text or "" for c in el)) + "}"
        else:
            value = el.get("value", "")
        out[name] = f"{el.tag}:{value}"
    return out


def _read_plist(path: Path) -> Dict[str, Value]:
    """plist를 펼친 경로 → 값으로 읽는다.

    Args:
        path: plist 경로.

    Returns:
        ``flatten_plist`` 결과.
    """
    return flatten_plist(plistlib.loads(_read_limited(path)))


def _read_limited(path: Path) -> bytes:
    """설정 파일을 상한까지만 읽는다.

    Args:
        path: 파일 경로.

    Returns:
        파일 내용.

    Raises:
        ValueError: 상한을 넘을 때.
    """
    with path.open("rb") as f:
        data = f.read(MAX_TEXT_ARTIFACT_BYTES + 1)
    if len(data) > MAX_TEXT_ARTIFACT_BYTES:
        raise ValueError("파일이 너무 큼")
    return data


def _diff_keyed(rel: str, kind: str, reader, b: Optional[Row], a: Optional[Row]) -> List[Row]:
    """키-값 형식 파일(설정 XML·plist)의 키 단위 차이를 구한다.

    Args:
        rel: 상대 경로.
        kind: 아티팩트 종류.
        reader: 경로 → 키-값 사전 함수.
        b: 행동 전 인벤토리 행(없었으면 None).
        a: 행동 후 인벤토리 행(없어졌으면 None).

    Returns:
        ``KEY_ADDED``/``KEY_DELETED``/``KEY_CHANGED`` 행. 읽지 못하면 ``PARSE_ERROR`` 한 행.
    """
    try:
        kb = reader(Path(str(b["path"]))) if b else {}
        ka = reader(Path(str(a["path"]))) if a else {}
    except Exception as e:   # 깨진 XML·plist, 상한 초과 등
        return [_row(rel, kind, "PARSE_ERROR", after=f"{type(e).__name__}: {e}")]
    out: List[Row] = []
    for key in sorted(set(kb) | set(ka)):
        if key not in kb:
            out.append(_row(rel, kind, "KEY_ADDED", key=key, after=_value_text(ka[key])))
        elif key not in ka:
            out.append(_row(rel, kind, "KEY_DELETED", key=key, before=_value_text(kb[key])))
        elif kb[key] != ka[key]:
            out.append(_row(rel, kind, "KEY_CHANGED", key=key,
                            before=_value_text(kb[key]), after=_value_text(ka[key])))
    return out


def _row(rel: str, artifact: str, change: str, *, scope: str = "", key: str = "", column: str = "",
         before: str = "", after: str = "") -> Row:
    """결과 행 하나를 만든다."""
    return {"rel_path": rel, "artifact": artifact, "change": change, "scope": scope, "key": key,
            "column": column, "before": before, "after": after}


def _file_summary(row: Optional[Row]) -> str:
    """파일 단위 변화에 남길 크기·해시 요약."""
    if not row:
        return ""
    return f"size={row.get('size_bytes')} sha256={str(row.get('sha256') or '')[:16]}"


def _sort_key(key: Tuple) -> Tuple:
    """행 키를 정렬할 키. 숫자는 숫자 순서(rowid 9 다음 10), 그 밖에는 문자열 순서다.

    Example:
        >>> sorted([("rowid", 10), ("rowid", 9)], key=_sort_key)
        [('rowid', 9), ('rowid', 10)]
    """
    return tuple((0, v, "") if isinstance(v, (int, float)) else (1, 0, str(v)) for v in key)


def _key_text(key: Tuple) -> str:
    """행 키를 결과용 문자열로 만든다(``rowid=3`` 또는 ``id=7, lang=ko``)."""
    if len(key) == 2 and key[0] == "rowid":
        return f"rowid={key[1]}"
    return ", ".join(_value_text(v) for v in key)


def _row_text(row: Dict[str, Value]) -> str:
    """행 전체를 ``열=값; 열=값`` 문자열로 만든다."""
    return "; ".join(f"{c}={_value_text(v)}" for c, v in row.items())


def _value_text(value: Value) -> str:
    """값을 결과용 문자열로 만든다. BLOB은 16진수, 긴 값은 앞부분과 길이를 남긴다.

    Example:
        >>> _value_text(b"\\x01\\x02")
        "x'0102'"
        >>> _value_text(None)
        'NULL'
    """
    if value is None:
        return "NULL"
    if isinstance(value, (bytes, bytearray)):
        text = f"x'{bytes(value).hex()}'"
        suffix = f"…({len(value)}바이트)"
    else:
        text = str(value)
        suffix = f"…({len(text)}자)"
    return text if len(text) <= MAX_VALUE_CHARS else text[:MAX_VALUE_CHARS] + suffix
