# make_dummy_evidence.py
from __future__ import annotations
import os, io, sys, time, json, shutil, random, string, zipfile, pathlib
from datetime import datetime, timedelta
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent 
ROOT = BASE_DIR / "ForensicTestData" 

def ensure_clean_root(root: pathlib.Path):
    if root.exists():
        print(f"[i] Removing old: {root}")
        shutil.rmtree(root)
    root.mkdir(parents=True)
    print(f"[+] Created root: {root}")

def write(path: pathlib.Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)

def write_text(path: pathlib.Path, s: str):
    write(path, s.encode("utf-8", errors="ignore"))

def rand_bytes(n: int) -> bytes:
    return os.urandom(n)

def make_fixed_content() -> bytes:
    # 동일 해시(중복 파일) 검증용 고정 콘텐츠
    random.seed(42)
    return ("DUPLICATE_CONTENT_" + ("x"*4096) + "_END").encode()

def png_bytes(width=1, height=1) -> bytes:
    # 미니멀한 1x1 PNG (시그니처 검증용)
    # 실제 PNG 시그니처 + 최소 IHDR/IDAT/​IEND 블록. 단순함을 위해 매우 작은 샘플 사용.
    return (b"\x89PNG\r\n\x1a\n"  # signature
            b"\x00\x00\x00\rIHDR"
            b"\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00"
            b"\x1f\x15\xc4\x89"
            b"\x00\x00\x00\x0AIDATx\x01\x01\x01\x00\xfe\xff\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00IEND\xaeB`\x82")

def jpeg_like_corrupted() -> bytes:
    # JPEG 마커 시작만 두고 뒤를 깨뜨려 손상파일처럼 만듦
    return b"\xff\xd8\xff\xe0" + b"THIS_IS_CORRUPTED_NOT_A_REAL_JPEG"

def big_file_chunks(total_mb=10, chunk_kb=256):
    chunks = (total_mb * 1024) // chunk_kb
    for _ in range(int(chunks)):
        yield os.urandom(chunk_kb * 1024)

def make_zip(zip_path: pathlib.Path, members: dict[str, bytes]):
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in members.items():
            zf.writestr(name, data)

def set_mtime(path: pathlib.Path, dt: datetime):
    ts = dt.timestamp()
    os.utime(path, (ts, ts))  # atime, mtime (Windows에서 ctime은 별도)

def main():
    ensure_clean_root(ROOT)

    # 디렉터리 구성
    docs = ROOT / "docs"
    images = ROOT / "images"
    bins = ROOT / "binaries"
    logs = ROOT / "logs"
    nested = ROOT / "nested"
    weird = ROOT / "weird names !@#$%^&()[]{};',"  # 특수문자 경로
    unicode_dir = ROOT / "유니코드_폴더"

    # 중복 파일(해시는 같고 이름/경로만 다른 케이스)
    dup_content = make_fixed_content()
    write(docs / "report_v1.txt", dup_content)
    write(docs / "copies" / "report_copy.txt", dup_content)

    # 0바이트 파일
    write(bins / "empty.bin", b"")

    # 대형 파일 (~10MB)
    big = bins / "big_random_10MB.bin"
    big.parent.mkdir(parents=True, exist_ok=True)
    with open(big, "wb") as f:
        for chunk in big_file_chunks(total_mb=10, chunk_kb=256):
            f.write(chunk)

    # 시그니처/확장자 불일치
    # PNG 시그니처이지만 확장자를 .jpg 로
    write(images / "mismatch_signature.jpg", png_bytes())
    # 진짜 PNG
    write(images / "true_image.png", png_bytes())

    # 손상 이미지 (JPEG처럼 보이긴 하는데 깨진다ㅇ)
    write(images / "corrupted_photo.jpg", jpeg_like_corrupted())

    # 일반 텍스트/CSV/JSON/로그
    write_text(docs / "notes.txt", "hello\nthis is a note\n")
    write_text(docs / "table.csv", "id,value\n1,10\n2,20\n3,30\n")
    write_text(docs / "meta.json", json.dumps({"case_id": 123, "owner": "alice"}, ensure_ascii=False, indent=2))
    write_text(logs / "app.log", "[2025-10-04 21:00:00] INFO start\n[2025-10-04 21:01:00] ERROR oops\n")

    # 압축파일
    make_zip(bins / "archive.zip", {
        "inner/readme.txt": b"This is inside zip\n",
        "inner/data.bin": os.urandom(2048),
    })

    # 유니코드/특수문자 파일명
    write(unicode_dir / "증거_파일_01.txt", b"UTF-8 content\n")
    write(weird / "strange file (final) [v3].txt", b"odd name\n")

    # 타임스탬프 다양화 (mtime만 파이썬으로 조정)
    now = datetime.now()
    set_mtime(docs / "report_v1.txt", now - timedelta(days=3))
    set_mtime(docs / "copies" / "report_copy.txt", now - timedelta(days=2, hours=5))
    set_mtime(bins / "empty.bin", now - timedelta(days=10))
    set_mtime(images / "mismatch_signature.jpg", now - timedelta(hours=1))
    set_mtime(images / "corrupted_photo.jpg", now - timedelta(minutes=5))

    # 깊은 중첩 경로
    write(nested / "deep_note.txt", b"very deep\n")

    # 심볼릭 링크(추후 확장 다시) 관리자 권한/개발자 모드 필요
    try:
        target = docs / "report_v1.txt"
        linkpath = ROOT / "symlinks" / "link_to_report.txt"
        linkpath.parent.mkdir(parents=True, exist_ok=True)
        os.symlink(target, linkpath)  # Windows: 관리자/Dev Mode 필요
        print("[+] Created symlink")
    except Exception as e:
        print(f"[!] Symlink skipped: {e}")

    # 대체 데이터 스트림(ADS, NTFS 전용·Windows에서만)
    if os.name == "nt":
        ads_target = (docs / "notes.txt").as_posix() + ":secret"
        try:
            with open(ads_target, "wb") as f:
                f.write(b"Hidden ADS content\n")
            print("[+] Created ADS on notes.txt")
        except Exception as e:
            print(f"[!] ADS skipped: {e}")

    print("\n[+] Done. Root:", ROOT)

if __name__ == "__main__":
    main()
