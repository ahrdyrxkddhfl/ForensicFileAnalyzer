# forensic_analyzer/dummy_test.py
"""테스트용 더미 증거 폴더(ForensicTestData)를 만든다.

기능별로 "잡아야 하는 사례"와 "잡으면 안 되는 사례"를 함께 넣는다.

- 확장자 위장: PNG 내용인 ``.jpg``(잡아야 함), 무작위 바이트인 ``.txt``(잡아야 함),
  텍스트 뒤에 무작위 데이터를 붙인 ``.txt``(잡아야 함), 정상 PNG·ZIP·텍스트(잡으면 안 됨)
- 앱 패키지: 일반 ZIP의 이름만 바꾼 ``.apk``(잡아야 함), APK 최소 구조를 갖춘 ``.apk``(잡으면 안 됨)
- 인코딩 검색: UTF-8, CP949(메모장 ANSI), UTF-16(메모장 유니코드) 한글 메모
- 해시: 내용이 같은 두 파일, 0바이트 파일, 10MB 파일(조각 단위 해시)
- 경로: 한글·특수문자 파일명, 깊은 폴더, 심볼릭 링크

무작위 데이터는 고정 시드로 만들어, 다시 실행해도 파일 내용이 바이트 단위로 같다.
그래서 이 스크립트를 다시 돌려도 git에 변경 사항이 생기지 않는다(수정 시각은 git이
추적하지 않는다).

Example:
    $ python forensic_analyzer/dummy_test.py            # 저장소의 ForensicTestData 재생성
    $ python forensic_analyzer/dummy_test.py /tmp/case  # 다른 위치에 생성
"""
from __future__ import annotations

import json
import os
import random
import shutil
import sys
import zipfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Optional

BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_ROOT = BASE_DIR / "ForensicTestData"
SEED = 42
FIXED_ZIP_TIME = (2025, 10, 4, 21, 0, 0)


def write(path: Path, data: bytes) -> None:
    """상위 폴더를 만들고 바이트를 파일로 쓴다.

    Args:
        path: 쓸 경로.
        data: 내용.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def png_bytes() -> bytes:
    """1x1 PNG의 최소 바이트열을 만든다(시그니처 검증용).

    Returns:
        PNG 시그니처로 시작하는 바이트열.
    """
    return (b"\x89PNG\r\n\x1a\n"
            b"\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89"
            b"\x00\x00\x00\x0aIDATx\x01\x01\x01\x00\xfe\xff\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00IEND\xaeB`\x82")


def make_zip(path: Path, members: Dict[str, bytes]) -> None:
    """수정 시각을 고정한 ZIP을 만든다(다시 만들어도 바이트가 같도록).

    Args:
        path: 만들 ZIP 경로.
        members: 압축 안 경로 → 내용.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in members.items():
            zf.writestr(zipfile.ZipInfo(name, date_time=FIXED_ZIP_TIME), data)


def set_mtime(path: Path, dt: datetime) -> None:
    """파일의 접근·수정 시각을 바꾼다(타임라인 검증용).

    Args:
        path: 대상 파일.
        dt: 설정할 시각.
    """
    ts = dt.timestamp()
    os.utime(path, (ts, ts))


def generate(root: Path = DEFAULT_ROOT) -> Path:
    """더미 증거 폴더를 새로 만든다. 기존 폴더는 지운다.

    Args:
        root: 만들 폴더 경로.

    Returns:
        만든 폴더 경로.
    """
    rng = random.Random(SEED)
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True)

    docs, images, bins = root / "docs", root / "images", root / "binaries"

    # 해시: 내용이 같은 두 파일 / 0바이트 / 10MB
    dup = b"DUPLICATE_CONTENT_" + b"x" * 4096 + b"_END"
    write(docs / "report_v1.txt", dup)
    write(docs / "copies" / "report_copy.txt", dup)
    write(bins / "empty.bin", b"")
    write(bins / "big_random_10MB.bin", rng.randbytes(10 * 1024 * 1024))

    # 확장자 위장: 잡아야 하는 사례
    write(images / "mismatch_signature.jpg", png_bytes())                    # 내용은 PNG
    write(docs / "secret.txt", rng.randbytes(4096))                          # 텍스트 아님(암호화 흉내)
    write(docs / "meeting_notes.txt",                                         # 텍스트 뒤에 데이터 은닉
          ("회의록\n" + "안건 검토 및 일정 공유\n" * 1500).encode("utf-8") + rng.randbytes(12000))

    # 확장자 위장: 잡으면 안 되는 사례
    write(images / "true_image.png", png_bytes())
    write(images / "corrupted_photo.jpg", b"\xff\xd8\xff\xe0" + b"THIS_IS_CORRUPTED_NOT_A_REAL_JPEG")
    make_zip(bins / "archive.zip", {"inner/readme.txt": b"This is inside zip\n",
                                    "inner/data.bin": rng.randbytes(2048)})

    # 앱 패키지: 최소 구조 APK(컴파일된 매니페스트 헤더 + DEX 헤더) / 일반 ZIP의 이름만 바꾼 APK
    apps = root / "apps"
    make_zip(apps / "structured_sample.apk", {"AndroidManifest.xml": b"\x03\x00\x08\x00" + bytes(60),
                                              "classes.dex": b"dex\n035\x00" + bytes(104)})
    make_zip(apps / "renamed_archive.apk", {"photos/img_001.jpg": b"\xff\xd8\xff\xe0" + bytes(64)})

    # 텍스트·인코딩
    write(docs / "notes.txt", b"hello\nthis is a note\n")
    write(docs / "table.csv", b"id,value\n1,10\n2,20\n3,30\n")
    write(docs / "meta.json", json.dumps({"case_id": 123, "owner": "alice"}, indent=2).encode())
    write(root / "logs" / "app.log", b"[2025-10-04 21:00:00] INFO start\n[2025-10-04 21:01:00] ERROR oops\n")
    write(docs / "memo_cp949.txt", "업무 메모\n비밀번호 변경 요청\n".encode("cp949"))   # 메모장 ANSI
    write(docs / "memo_utf16.txt", "업무 메모\n비밀번호 초기화\n".encode("utf-16"))    # 메모장 유니코드

    # 경로: 한글·특수문자 이름, 깊은 폴더
    write(root / "유니코드_폴더" / "증거_파일_01.txt", b"UTF-8 content\n")
    write(root / "weird names !@#$%^&()[]{};'," / "strange file (final) [v3].txt", b"odd name\n")
    write(root / "nested" / "deep_note.txt", b"very deep\n")

    # 타임라인용 수정 시각
    now = datetime.now()
    set_mtime(docs / "report_v1.txt", now - timedelta(days=3))
    set_mtime(docs / "copies" / "report_copy.txt", now - timedelta(days=2, hours=5))
    set_mtime(bins / "empty.bin", now - timedelta(days=10))
    set_mtime(images / "mismatch_signature.jpg", now - timedelta(hours=1))
    set_mtime(images / "corrupted_photo.jpg", now - timedelta(minutes=5))

    # 심볼릭 링크(상대 경로라 저장소를 옮겨도 유지됨). Windows는 관리자/개발자 모드 필요.
    link = root / "symlinks" / "link_to_report.txt"
    link.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.symlink(os.path.join("..", "docs", "report_v1.txt"), link)
        print("[+] Created symlink")
    except (OSError, NotImplementedError) as e:
        print(f"[!] Symlink skipped: {e}")

    # NTFS 대체 데이터 스트림(Windows 전용)
    if os.name == "nt":
        try:
            with open(str(docs / "notes.txt") + ":secret", "wb") as f:
                f.write(b"Hidden ADS content\n")
            print("[+] Created ADS on notes.txt")
        except OSError as e:
            print(f"[!] ADS skipped: {e}")

    print(f"[+] Done. Root: {root}")
    return root


def main(argv: Optional[list] = None) -> None:
    """명령줄 진입점. 인자로 경로를 주면 그 위치에 만든다.

    Args:
        argv: 명령줄 인자(테스트용). None이면 ``sys.argv[1:]``.
    """
    argv = sys.argv[1:] if argv is None else argv
    generate(Path(argv[0]) if argv else DEFAULT_ROOT)


if __name__ == "__main__":
    main()
