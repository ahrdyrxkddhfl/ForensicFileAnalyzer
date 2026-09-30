# main.py
from __future__ import annotations
import argparse
import csv
import hashlib
from pathlib import Path
from typing import Dict, List, Union

# 내부 모듈
from forensic_analyzer.inventory import collect_inventory
from forensic_analyzer.hashing import add_hashes_to_rows
from forensic_analyzer.signature import add_signature_to_rows
from forensic_analyzer.search import search_texts, write_hits_csv
from forensic_analyzer.timeline import build_timeline_rows, write_timeline_csv
from forensic_analyzer.validate import (
    validate_inventory_rows, sample_verify_hashes,
    write_issues_csv, summarize_issues,
    load_inventory_csv, compare_with_baseline,
)
from forensic_analyzer.foroutput import ensure_dir, make_outpath


def _normalize_hash_algorithms(
    algorithms: List[str], parser: argparse.ArgumentParser
) -> List[str]:
    """해시 알고리즘 이름을 소문자로 통일하고, 이 도구에서 쓸 수 있는지 미리 검사한다.

    스캔이 다 끝난 뒤에 실패하지 않도록 파일을 읽기 전에 검사한다.

    - 대소문자를 통일한다. ``SHA256``을 그대로 쓰면 CSV 열 이름이 ``SHA256``이 되어
      기준본의 ``sha256`` 열과 짝이 맞지 않기 때문이다.
    - ``shake_128``처럼 출력 길이를 따로 지정해야 하는 알고리즘은 거부한다.
      ``hexdigest()``를 인자 없이 호출할 수 없어 스캔 뒤에 TypeError가 나기 때문이다.
    - 중복은 한 번만 남긴다.

    Args:
        algorithms: 사용자가 ``--hash-algorithms``로 준 이름 목록.
        parser: 오류 메시지를 출력하고 종료할 파서.

    Returns:
        정규화한 알고리즘 이름 목록.

    Example:
        >>> _normalize_hash_algorithms(["SHA256", "md5", "sha256"], parser)
        ['sha256', 'md5']
    """
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


# CSV 저장
def _ensure_parent(path: Union[str, Path]) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    return p

def _write_csv_dynamic(rows: List[Dict[str, object]], out_path: Union[str, Path]) -> None:

    if not rows:
        print(f"[WARN] No rows to write to {out_path}")
        return

    out = _ensure_parent(out_path)
    preferred = [
        "path", "rel_path", "name", "parent", "size_bytes",
        "mtime_epoch", "atime_epoch", "ctime_epoch", "birthtime_epoch",
        "is_symlink", "md5", "sha256",
        "sig_mime", "sig_ext", "sig_desc", "sig_source", "sig_high_entropy", "ext_on_disk", "ext_mismatch",
    ]
    keys_order: List[str] = []
    seen = set(preferred)
    keys_order.extend(preferred)
    
    for r in rows:
        for k in r.keys():
            if k not in seen:
                seen.add(k)
                keys_order.append(k)

    with open(out, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=keys_order, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)

    print(f"[OK] saved {len(rows)} rows -> {out}")


# inventory 서브커맨드
def cmd_inventory(args: argparse.Namespace) -> None:
    print("[DBG] running inventory, root=", args.root)
    rows = collect_inventory(
        args.root,
        follow_symlinks=args.follow_symlinks,
        exclude_globs=args.exclude,
    )

    if args.with_hash:
        rows = add_hashes_to_rows(
            rows,
            algorithms=tuple(args.hash_algorithms),
            chunk_size=args.hash_block_size,
        )

    if args.with_signature:
        rows = add_signature_to_rows(
            rows,
            prefer_magic=not args.sig_no_magic,
            disk_ext_field="ext_on_disk",
            sig_prefix="sig_",
        )

    out_dir = ensure_dir(Path(args.out_dir))
    out_path = Path(args.out) if args.out else make_outpath("inventory", out_dir, args.label)
    _write_csv_dynamic(rows, out_path)


# search 서브커맨드
def cmd_search(args: argparse.Namespace) -> None:
    if not args.keywords:
        raise SystemExit("[-] 검색할 키워드가 필요합니다 (예: --kw password --kw token)")
    
    print("[DBG] running search, root=", args.root)
    hits = search_texts(
        root=args.root,
        keywords=args.keywords,
        use_regex=args.regex,
        case_sensitive=args.case_sensitive,
        include_exts=tuple(args.include_exts),
        exclude_globs=args.exclude,
        follow_symlinks=args.follow_symlinks,
        # max_file_size_bytes와 preview_len은 argparse에 추가되지 않았으므로 기본값 사용
    )

    out_dir = ensure_dir(Path(args.out_dir))
    out_hits = Path(args.out_hits) if args.out_hits else make_outpath("search", out_dir, args.label)
    write_hits_csv(hits, out_hits)
    print(f"[OK] {len(hits)} hits -> {out_hits}")


# timeline 서브커맨드
def cmd_timeline(args: argparse.Namespace) -> None:
    print("[DBG] running timeline, root=", args.root)
    rows = collect_inventory(
        args.root,
        follow_symlinks=args.follow_symlinks,
        exclude_globs=args.exclude,
    )

    if args.with_hash:
        rows = add_hashes_to_rows(rows, algorithms=tuple(args.hash_algorithms), chunk_size=args.hash_block_size)
    if args.with_signature:
        rows = add_signature_to_rows(rows, prefer_magic=not args.sig_no_magic)

    tl_rows = build_timeline_rows(
        rows,
        tz_offset_minutes=getattr(args, 'tz_offset_min', None),
    )

    out_dir = ensure_dir(Path(args.out_dir))
    out_timeline = Path(args.out_timeline) if args.out_timeline else make_outpath("timeline", out_dir, args.label)
    write_timeline_csv(tl_rows, out_timeline)
    print(f"[OK] {len(tl_rows)} events -> {out_timeline}")

    if getattr(args, 'out_inventory', None):
        inv_out = Path(args.out_inventory)
        _write_csv_dynamic(rows, inv_out)


# validate 서브커맨드
def cmd_validate(args: argparse.Namespace) -> None:
    """validate 서브커맨드: 인벤토리 기본 검증과 (선택) 기준본 비교를 수행한다.

    ``--verify-hash``나 ``--baseline``을 주면 해시가 필요하므로 ``--with-hash``를
    자동으로 켠다.

    Args:
        args: argparse 결과. ``root``, ``baseline``, ``verify_hash`` 등을 사용한다.
    """
    print("[DBG] running validate, root=", args.root)
    if args.verify_hash or args.baseline:
        args.with_hash = True
    rows = collect_inventory(
        args.root,
        follow_symlinks=args.follow_symlinks,
        exclude_globs=args.exclude,
    )

    if args.with_hash:
        rows = add_hashes_to_rows(rows, algorithms=tuple(args.hash_algorithms), chunk_size=args.hash_block_size)
    if args.with_signature:
        rows = add_signature_to_rows(rows, prefer_magic=not args.sig_no_magic)

    issues = []
    issues += validate_inventory_rows(rows) 

    if getattr(args, 'verify_hash', False):
        issues += sample_verify_hashes(
            rows,
            algorithms=tuple(args.hash_algorithms),
            chunk_size=args.hash_block_size,
        )

    if args.baseline:
        baseline_rows = args.baseline_rows  # main()에서 형식 검사를 마친 기준본
        issues += compare_with_baseline(
            rows, baseline_rows, algorithms=tuple(args.hash_algorithms)
        )
        print(f"[INFO] compared with baseline: {args.baseline} ({len(baseline_rows)} rows)")

    out_dir = ensure_dir(Path(args.out_dir))
    out_issues = Path(args.out_issues) if args.out_issues else make_outpath("validate", out_dir, args.label)
    write_issues_csv(issues, out_issues)
    summary = summarize_issues(issues)
    print(f"[OK] issues: {len(issues)} -> {out_issues}")
    print("[SUMMARY]", summary)

    if getattr(args, 'out_inventory', None):
        inv_out = Path(args.out_inventory)
        _write_csv_dynamic(rows, inv_out)


# argparse 설정
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ForensicFileAnalyzer", description="ForensicFileAnalyzer CLI")
    sub = p.add_subparsers(dest="command", required=True, help="Available commands")

    def add_common_opts(sp: argparse.ArgumentParser):
        sp.add_argument("root", help="스캔할 루트 폴더 경로")
        sp.add_argument("--out-dir", default="outputs", help="결과 CSV 저장 폴더")
        sp.add_argument("--label", default="", help="파일명에 붙일 라벨")
        sp.add_argument("--exclude", nargs="*", default=["*/.git/*", "*/node_modules/*"], help="제외할 글롭 패턴")
        sp.add_argument("--follow-symlinks", action="store_true", help="심볼릭 링크를 따라감")
        sp.add_argument("--with-hash", action="store_true", help="MD5/SHA-256 해시 열 추가")
        sp.add_argument("--hash-algorithms", nargs="*", default=["md5", "sha256"])
        sp.add_argument("--hash-block-size", type=int, default=1024*1024)
        sp.add_argument("--with-signature", action="store_true", help="파일 시그니처 판정 열 추가")
        sp.add_argument("--sig-no-magic", action="store_true", help="libmagic 미사용")

    # inventory 
    inv = sub.add_parser("inventory", help="파일 인벤토리 & 메타데이터 추출")
    add_common_opts(inv)
    inv.add_argument("--out", default="", help="결과 CSV 파일 경로 지정")
    inv.set_defaults(func=cmd_inventory)

    # search 
    sea = sub.add_parser("search", help="텍스트 파일 키워드 검색")
    add_common_opts(sea)
    sea.add_argument("--out-hits", default="", help="검색 결과 CSV 파일 경로")
    sea.add_argument("--kw", dest="keywords", action="append", default=[], help="검색 키워드/패턴")
    sea.add_argument("--regex", action="store_true", help="키워드를 정규식으로 처리")
    sea.add_argument("--case-sensitive", action="store_true", help="대소문자 구분")
    sea.add_argument("--include-exts", nargs="*", default=["txt", "log", "csv", "json", "xml", "md"])
    sea.set_defaults(func=cmd_search)

    # timeline 
    tli = sub.add_parser("timeline", help="파일 시간 정보로 타임라인 생성")
    add_common_opts(tli)
    tli.add_argument("--out-timeline", default="", help="타임라인 CSV 파일 경로")
    tli.add_argument("--tz-offset-min", type=int, help="타임존 오프셋(분)")
    tli.add_argument("--out-inventory", help="타임라인 생성에 사용된 원본 인벤토리도 저장")
    tli.set_defaults(func=cmd_timeline)
    
    # validate 
    val = sub.add_parser("validate", help="데이터 무결성 검증")
    add_common_opts(val)
    val.add_argument("--out-issues", default="", help="검증 이슈 CSV 파일 경로")
    val.add_argument("--verify-hash", action="store_true", help="해시 샘플 재계산 일관성 검사")
    val.add_argument("--baseline", default="", help="이전 inventory CSV와 비교해 변경·삭제·추가 탐지")
    val.add_argument("--out-inventory", help="검증에 사용된 원본 인벤토리도 저장")
    val.set_defaults(func=cmd_validate)

    return p


def main() -> None:
    """CLI 진입점. 인자를 파싱하고 입력값을 검사한 뒤 서브커맨드를 실행한다.

    잘못된 입력은 스캔을 시작하기 전에 오류로 종료한다. 오타 난 경로를
    "파일이 없는 폴더"로 오해하거나, 긴 스캔이 끝난 뒤에야 실패하는 일을 막기 위함이다.
    """
    parser = build_parser()
    args = parser.parse_args()

    root = getattr(args, "root", None)
    if root is not None and not Path(root).is_dir():
        parser.error(f"root 경로가 없거나 폴더가 아닙니다: {root}")

    if hasattr(args, "hash_algorithms"):
        args.hash_algorithms = _normalize_hash_algorithms(args.hash_algorithms, parser)

    baseline = getattr(args, "baseline", "")
    if baseline:
        if not Path(baseline).is_file():
            parser.error(f"기준본 CSV를 찾을 수 없습니다: {baseline}")
        try:
            args.baseline_rows = load_inventory_csv(baseline)
        except ValueError as e:
            parser.error(str(e))

    if hasattr(args, 'func'):
        args.func(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()