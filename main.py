# main.py
"""ForensicFileAnalyzer 명령줄 진입점.

명령:
    inventory  파일 목록·메타데이터(선택: 해시, 시그니처) 수집
    search     텍스트 파일 키워드·정규식 검색
    timeline   파일 시간 정보로 시간순 사건 목록 생성
    validate   인벤토리 검증과 기준본(예전 인벤토리) 비교

모든 입력값은 스캔을 시작하기 전에 검사한다. 긴 스캔이 끝난 뒤에야 잘못된 옵션
때문에 실패하거나, 오타 난 경로를 "파일 없는 폴더"로 오해하는 일을 막기 위함이다.

Example:
    $ python main.py inventory ForensicTestData --with-hash --with-signature
    $ python main.py validate ForensicTestData --baseline outputs/baseline.csv
"""
from __future__ import annotations

import argparse
import codecs
import hashlib
import re
import sys
from pathlib import Path
from typing import Dict, List, Sequence

from forensic_analyzer.foroutput import ensure_dir, make_outpath, write_rows_csv
from forensic_analyzer.hashing import add_hashes_to_rows
from forensic_analyzer.inventory import INVENTORY_FIELDS, collect_inventory
from forensic_analyzer.search import (
    DEFAULT_ENCODINGS, DEFAULT_INCLUDE_EXTS, HIT_FIELDS, SKIP_FIELDS, compile_patterns, search_texts,
)
from forensic_analyzer.signature import add_signature_to_rows
from forensic_analyzer.timeline import TIMELINE_FIELDS, build_timeline_rows
from forensic_analyzer.validate import (
    ISSUE_FIELDS, Issue, compare_with_baseline, issues_to_rows, load_inventory_csv,
    sample_verify_hashes, summarize_issues, validate_inventory_rows,
)

SIGNATURE_FIELDS = ("sig_mime", "sig_ext", "sig_desc", "sig_source", "sig_high_entropy", "ext_on_disk", "ext_mismatch")
ERROR_FIELDS = ("path", "reason")


# ---------------------------------------------------------------------------
# 공통 처리
# ---------------------------------------------------------------------------

def inventory_fieldnames(hash_algorithms: Sequence[str]) -> List[str]:
    """인벤토리 CSV의 열 순서를 만든다.

    Args:
        hash_algorithms: 계산한 해시 알고리즘 목록.

    Returns:
        기본 열 → 해시 열 → 해시 상태 → 시그니처 열 순서의 목록.
    """
    return [*INVENTORY_FIELDS, *hash_algorithms, "hash_status", *SIGNATURE_FIELDS]


def build_inventory(args: argparse.Namespace, errors: List[Dict[str, str]]) -> List[Dict[str, object]]:
    """인벤토리를 수집하고, 옵션에 따라 해시·시그니처를 붙인다.

    Args:
        args: 파싱된 명령줄 인자.
        errors: 읽지 못한 폴더·파일을 기록할 리스트.

    Returns:
        인벤토리 행 리스트.
    """
    rows = collect_inventory(args.root, follow_symlinks=args.follow_symlinks,
                             exclude_globs=args.exclude, errors=errors)
    if args.with_hash:
        add_hashes_to_rows(rows, algorithms=tuple(args.hash_algorithms), chunk_size=args.hash_block_size,
                           follow_symlinks=args.follow_symlinks)
    if args.with_signature:
        add_signature_to_rows(rows, prefer_magic=not args.sig_no_magic, follow_symlinks=args.follow_symlinks)
    return rows


def write_inventory(rows: List[Dict[str, object]], path: Path, args: argparse.Namespace) -> None:
    """인벤토리 CSV를 저장하고 결과를 출력한다.

    Args:
        rows: 인벤토리 행.
        path: 저장 경로.
        args: 파싱된 명령줄 인자(해시 알고리즘 목록 참조).
    """
    algos = args.hash_algorithms if args.with_hash else []
    write_rows_csv(rows, path, preferred=inventory_fieldnames(algos))
    print(f"[OK] saved {len(rows)} rows -> {path}")


def report_scan_errors(errors: List[Dict[str, str]], main_out: Path) -> None:
    """스캔 중 읽지 못한 항목이 있으면 경고를 출력하고 별도 CSV로 저장한다.

    Args:
        errors: ``collect_inventory``가 기록한 오류 목록.
        main_out: 주 결과 파일 경로. 같은 폴더에 ``<이름>_errors.csv``로 저장한다.
    """
    if not errors:
        return
    err_path = main_out.with_name(f"{main_out.stem}_errors.csv")
    write_rows_csv(errors, err_path, preferred=ERROR_FIELDS)
    print(f"[WARN] {len(errors)} items could not be read -> {err_path}")


# ---------------------------------------------------------------------------
# 서브커맨드
# ---------------------------------------------------------------------------

def cmd_inventory(args: argparse.Namespace) -> None:
    """inventory: 파일 목록과 메타데이터를 수집해 CSV로 저장한다.

    Args:
        args: 파싱된 명령줄 인자.
    """
    print(f"[INFO] inventory root={args.root}")
    errors: List[Dict[str, str]] = []
    rows = build_inventory(args, errors)
    out_path = Path(args.out) if args.out else make_outpath("inventory", ensure_dir(Path(args.out_dir)), args.label)
    write_inventory(rows, out_path, args)
    report_scan_errors(errors, out_path)


def cmd_search(args: argparse.Namespace) -> None:
    """search: 텍스트 파일에서 키워드를 찾고, 검색하지 못한 파일도 따로 기록한다.

    Args:
        args: 파싱된 명령줄 인자.
    """
    print(f"[INFO] search root={args.root}")
    skipped: List[Dict[str, object]] = []
    hits = search_texts(
        args.root, args.keywords, use_regex=args.regex, case_sensitive=args.case_sensitive,
        include_exts=tuple(args.include_exts), exclude_globs=args.exclude, follow_symlinks=args.follow_symlinks,
        max_file_size_bytes=int(args.max_size_mb * 1024 * 1024), encodings=tuple(args.encodings), skipped=skipped,
    )
    out_hits = Path(args.out_hits) if args.out_hits else make_outpath("search", ensure_dir(Path(args.out_dir)), args.label)
    write_rows_csv(hits, out_hits, preferred=HIT_FIELDS)
    print(f"[OK] {len(hits)} hits -> {out_hits}")
    if skipped:
        skip_path = out_hits.with_name(f"{out_hits.stem}_skipped.csv")
        write_rows_csv(skipped, skip_path, preferred=SKIP_FIELDS)
        print(f"[WARN] {len(skipped)} files not searched -> {skip_path}")


def cmd_timeline(args: argparse.Namespace) -> None:
    """timeline: 파일 시간 정보를 시간순 사건 목록으로 저장한다.

    Args:
        args: 파싱된 명령줄 인자.
    """
    print(f"[INFO] timeline root={args.root}")
    errors: List[Dict[str, str]] = []
    rows = build_inventory(args, errors)
    tl_rows = build_timeline_rows(rows, tz_offset_minutes=args.tz_offset_min)
    out_path = Path(args.out_timeline) if args.out_timeline else make_outpath("timeline", ensure_dir(Path(args.out_dir)), args.label)
    write_rows_csv(tl_rows, out_path, preferred=TIMELINE_FIELDS)
    print(f"[OK] {len(tl_rows)} events -> {out_path}")
    report_scan_errors(errors, out_path)
    if args.out_inventory:
        write_inventory(rows, Path(args.out_inventory), args)


def cmd_validate(args: argparse.Namespace) -> None:
    """validate: 인벤토리를 검증하고, 기준본이 있으면 비교한다.

    ``--verify-hash``나 ``--baseline``을 주면 해시가 필요하므로 ``--with-hash``를 자동으로 켠다.

    Args:
        args: 파싱된 명령줄 인자.
    """
    print(f"[INFO] validate root={args.root}")
    if args.verify_hash or args.baseline:
        args.with_hash = True
    errors: List[Dict[str, str]] = []
    rows = build_inventory(args, errors)

    algos = tuple(args.hash_algorithms) if args.with_hash else ()
    issues: List[Issue] = validate_inventory_rows(rows, follow_symlinks=args.follow_symlinks, hash_algorithms=algos)
    issues += [Issue(e["path"], "SCAN_ERROR", "WARN", e["reason"]) for e in errors]
    if args.verify_hash:
        issues += sample_verify_hashes(rows, algorithms=algos, chunk_size=args.hash_block_size)
    if args.baseline:
        issues += compare_with_baseline(rows, args.baseline_rows, algorithms=algos)
        print(f"[INFO] compared with baseline: {args.baseline} ({len(args.baseline_rows)} rows)")

    out_path = Path(args.out_issues) if args.out_issues else make_outpath("validate", ensure_dir(Path(args.out_dir)), args.label)
    write_rows_csv(issues_to_rows(issues), out_path, preferred=ISSUE_FIELDS)
    print(f"[OK] issues: {len(issues)} -> {out_path}")
    print("[SUMMARY]", summarize_issues(issues))
    if args.out_inventory:
        write_inventory(rows, Path(args.out_inventory), args)


# ---------------------------------------------------------------------------
# 인자 파싱과 사전 검사
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    """명령줄 파서를 만든다.

    Returns:
        서브커맨드가 등록된 ``ArgumentParser``.
    """
    p = argparse.ArgumentParser(prog="ForensicFileAnalyzer", description="ForensicFileAnalyzer CLI")
    sub = p.add_subparsers(dest="command", required=True, help="Available commands")

    def add_common_opts(sp: argparse.ArgumentParser) -> None:
        """모든 서브커맨드가 공유하는 옵션(루트, 출력, 제외, 링크, 해시, 시그니처)을 등록한다.

        Args:
            sp: 옵션을 추가할 서브커맨드 파서.
        """
        sp.add_argument("root", help="스캔할 루트 폴더 경로")
        sp.add_argument("--out-dir", default="outputs", help="결과 CSV 저장 폴더")
        sp.add_argument("--label", default="", help="파일명에 붙일 사건 라벨")
        sp.add_argument("--exclude", nargs="*", default=["*/.git/*", "*/node_modules/*"], help="제외할 글롭 패턴")
        sp.add_argument("--follow-symlinks", action="store_true", help="심볼릭 링크를 따라감(순환 링크는 자동 차단)")
        sp.add_argument("--with-hash", action="store_true", help="해시 열 추가")
        sp.add_argument("--hash-algorithms", nargs="*", default=["md5", "sha256"], help="해시 알고리즘(소문자로 통일)")
        sp.add_argument("--hash-block-size", type=int, default=1024 * 1024, help="해시 계산 시 읽기 단위(바이트)")
        sp.add_argument("--with-signature", action="store_true", help="파일 시그니처 판별 열 추가")
        sp.add_argument("--sig-no-magic", action="store_true", help="libmagic을 쓰지 않고 내장 판별만 사용")

    inv = sub.add_parser("inventory", help="파일 인벤토리 & 메타데이터 추출")
    add_common_opts(inv)
    inv.add_argument("--out", default="", help="결과 CSV 파일 경로 지정")
    inv.set_defaults(func=cmd_inventory)

    sea = sub.add_parser("search", help="텍스트 파일 키워드 검색")
    add_common_opts(sea)
    sea.add_argument("--out-hits", default="", help="검색 결과 CSV 파일 경로")
    sea.add_argument("--kw", dest="keywords", action="append", default=[], help="검색 키워드/패턴(여러 번 지정 가능)")
    sea.add_argument("--regex", action="store_true", help="키워드를 정규식으로 처리")
    sea.add_argument("--case-sensitive", action="store_true", help="대소문자 구분")
    sea.add_argument("--include-exts", nargs="*", default=list(DEFAULT_INCLUDE_EXTS), help="검색 대상 확장자")
    sea.add_argument("--encodings", nargs="*", default=list(DEFAULT_ENCODINGS),
                     help="BOM이 없을 때 시도할 인코딩 순서(예: utf-8 shift_jis)")
    sea.add_argument("--max-size-mb", type=float, default=10.0, help="이보다 큰 파일은 건너뛰고 기록(MB)")
    sea.set_defaults(func=cmd_search)

    tli = sub.add_parser("timeline", help="파일 시간 정보로 타임라인 생성")
    add_common_opts(tli)
    tli.add_argument("--out-timeline", default="", help="타임라인 CSV 파일 경로")
    tli.add_argument("--tz-offset-min", type=int, help="표시 시간대 오프셋(분). 예: KST=540")
    tli.add_argument("--out-inventory", default="", help="타임라인에 사용한 인벤토리도 저장")
    tli.set_defaults(func=cmd_timeline)

    val = sub.add_parser("validate", help="데이터 무결성 검증")
    add_common_opts(val)
    val.add_argument("--out-issues", default="", help="검증 이슈 CSV 파일 경로")
    val.add_argument("--verify-hash", action="store_true", help="해시 표본 재계산으로 계산 일관성 검사")
    val.add_argument("--baseline", default="", help="이전 inventory CSV와 비교해 변경·삭제·추가·이동 탐지")
    val.add_argument("--out-inventory", default="", help="검증에 사용한 인벤토리도 저장")
    val.set_defaults(func=cmd_validate)
    return p


def normalize_hash_algorithms(algorithms: List[str], parser: argparse.ArgumentParser) -> List[str]:
    """해시 알고리즘 이름을 소문자로 통일하고, 쓸 수 있는지 미리 검사한다.

    - ``SHA256``을 그대로 쓰면 CSV 열 이름이 달라져 기준본의 ``sha256``과 짝이 맞지 않는다.
    - ``shake_128``처럼 출력 길이를 지정해야 하는 알고리즘은 ``hexdigest()``를 인자 없이
      부를 수 없어 스캔 뒤에 실패하므로 미리 거부한다.
    - 중복은 한 번만 남긴다.

    Args:
        algorithms: ``--hash-algorithms``로 받은 이름 목록.
        parser: 오류를 출력하고 종료할 파서.

    Returns:
        정규화한 이름 목록.

    Example:
        >>> normalize_hash_algorithms(["SHA256", "md5", "sha256"], parser)  # doctest: +SKIP
        ['sha256', 'md5']
    """
    if not algorithms:
        parser.error("--hash-algorithms에 알고리즘을 하나 이상 지정해야 합니다")
    normalized: List[str] = []
    for algo in algorithms:
        name = algo.strip().lower()
        try:
            hashlib.new(name).hexdigest()
        except ValueError:
            parser.error(f"지원하지 않는 해시 알고리즘: {algo}")
        except TypeError:
            parser.error(f"출력 길이를 지정해야 하는 알고리즘은 쓸 수 없습니다: {algo}")
        if name not in normalized:
            normalized.append(name)
    return normalized


def validate_args(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    """스캔을 시작하기 전에 모든 입력값을 검사한다. 문제가 있으면 오류로 종료한다.

    Args:
        args: 파싱된 명령줄 인자. 일부 값은 정규화된 값으로 바뀐다.
        parser: 오류를 출력하고 종료할 파서.
    """
    if not Path(args.root).is_dir():
        parser.error(f"root 경로가 없거나 폴더가 아닙니다: {args.root}")
    if Path(args.out_dir).exists() and not Path(args.out_dir).is_dir():
        parser.error(f"--out-dir가 폴더가 아닙니다: {args.out_dir}")

    args.hash_algorithms = normalize_hash_algorithms(args.hash_algorithms, parser)
    if args.hash_block_size < 1:
        parser.error("--hash-block-size는 1 이상이어야 합니다")

    if args.command == "search":
        if not args.keywords:
            parser.error("검색할 키워드가 필요합니다 (예: --kw password --kw 비밀번호)")
        try:
            compile_patterns(args.keywords, use_regex=args.regex, case_sensitive=args.case_sensitive)
        except re.error as e:
            parser.error(f"정규식 오류: {e}")
        if args.max_size_mb <= 0:
            parser.error("--max-size-mb는 0보다 커야 합니다")
        if not args.encodings:
            parser.error("--encodings에 인코딩을 하나 이상 지정해야 합니다")
        for enc in args.encodings:
            try:
                codecs.lookup(enc)
            except LookupError:
                parser.error(f"알 수 없는 인코딩: {enc}")

    if args.command == "timeline" and args.tz_offset_min is not None and not -1439 <= args.tz_offset_min <= 1439:
        parser.error("--tz-offset-min은 -1439~1439 사이여야 합니다")

    if args.command == "validate" and args.baseline:
        if not Path(args.baseline).is_file():
            parser.error(f"기준본 CSV를 찾을 수 없습니다: {args.baseline}")
        try:
            args.baseline_rows = load_inventory_csv(args.baseline)
        except ValueError as e:
            parser.error(str(e))


def main(argv: Sequence[str] | None = None) -> None:
    """CLI 진입점. 인자를 파싱·검사한 뒤 서브커맨드를 실행한다.

    Args:
        argv: 테스트용 인자 목록. None이면 ``sys.argv``를 쓴다.
    """
    parser = build_parser()
    args = parser.parse_args(argv)
    validate_args(args, parser)
    args.func(args)


if __name__ == "__main__":
    main(sys.argv[1:])
