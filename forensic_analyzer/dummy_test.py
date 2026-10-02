# forensic_analyzer/dummy_test.py
"""테스트용 더미 증거 폴더(ForensicTestData)를 만든다.

기능별로 "잡아야 하는 사례"와 "잡으면 안 되는 사례"를 함께 넣는다.

- 확장자 위장: PNG 내용인 ``.jpg``(잡아야 함), 무작위 바이트인 ``.txt``(잡아야 함),
  텍스트 뒤에 무작위 데이터를 붙인 ``.txt``(잡아야 함), 정상 PNG·ZIP·텍스트(잡으면 안 됨)
- 앱 패키지: 일반 ZIP의 이름만 바꾼 ``.apk``(잡아야 함), 컴파일된 매니페스트를 갖춘 ``.apk``·
  IPA·``.zip``으로 둔 APK(잡으면 안 됨, ``apps`` 명령에서 정보가 나와야 함)
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
import plistlib
import random
import shutil
import struct
import sys
import zipfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple, Union

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


# 안드로이드 공개 속성의 리소스 ID(android.R.attr). 컴파일된 매니페스트는 속성을 이 ID로 식별한다.
ANDROID_NS = "http://schemas.android.com/apk/res/android"
_ATTR_IDS = {"name": 0x01010003, "label": 0x01010001, "versionCode": 0x0101021B, "versionName": 0x0101021C,
             "minSdkVersion": 0x0101020C, "targetSdkVersion": 0x01010270}
_NONE = 0xFFFFFFFF
_TYPE_STRING, _TYPE_INT_DEC = 0x03, 0x10

# (태그, [(android 네임스페이스 여부, 속성 이름, 값)], 자식 요소들)
Element = Tuple[str, List[Tuple[bool, str, Union[str, int]]], list]


def android_manifest_bytes(package: str, version_code: int, version_name: str, min_sdk: int, target_sdk: int,
                           permissions: Sequence[str], label: str) -> bytes:
    """빌드 도구(aapt2)가 만드는 것과 같은 형식의 컴파일된 AndroidManifest.xml을 만든다.

    실제 APK를 저장소에 넣지 않고도 APK 정보 추출을 테스트하기 위한 것이다. 구조는
    파일 헤더 → 문자열 표 → 리소스 ID 표 → 네임스페이스·요소 시작/끝 청크 순서다.

    Args:
        package: 패키지명.
        version_code: 버전 코드.
        version_name: 버전 이름.
        min_sdk: 최소 SDK.
        target_sdk: 대상 SDK.
        permissions: 요청 권한.
        label: 앱 이름.

    Returns:
        ``03 00 08 00``으로 시작하는 바이너리 XML.
    """
    attr = lambda name, value: (True, name, value)  # noqa: E731
    root: Element = ("manifest", [(False, "package", package), attr("versionCode", version_code),
                                  attr("versionName", version_name)],
                     [("uses-sdk", [attr("minSdkVersion", min_sdk), attr("targetSdkVersion", target_sdk)], [])]
                     + [("uses-permission", [attr("name", p)], []) for p in permissions]
                     + [("application", [attr("label", label)], [])])

    # 리소스 ID가 붙는 속성 이름은 문자열 표 맨 앞에 두고, ID 표의 순서와 맞춘다.
    strings: List[str] = [*_ATTR_IDS, "android", ANDROID_NS]

    def idx(text: str) -> int:
        if text not in strings:
            strings.append(text)
        return strings.index(text)

    def element(node: Element) -> bytes:
        tag, attrs, children = node
        body = b""
        for in_ns, name, value in attrs:
            ns = idx(ANDROID_NS) if in_ns else _NONE
            if isinstance(value, str):
                body += struct.pack("<IIIHBBI", ns, idx(name), idx(value), 8, 0, _TYPE_STRING, idx(value))
            else:
                body += struct.pack("<IIIHBBI", ns, idx(name), _NONE, 8, 0, _TYPE_INT_DEC, value)
        start = struct.pack("<HHIIIIIHHHHHH", 0x0102, 16, 36 + len(body), 1, _NONE, _NONE, idx(tag),
                            20, 20, len(attrs), 0, 0, 0) + body
        inner = b"".join(element(c) for c in children)
        return start + inner + struct.pack("<HHIIIII", 0x0103, 16, 24, 1, _NONE, _NONE, idx(tag))

    ns = struct.pack("<HHIIIII", 0x0100, 16, 24, 1, _NONE, idx("android"), idx(ANDROID_NS))
    tree = ns + element(root) + struct.pack("<HHIIIII", 0x0101, 16, 24, 1, _NONE, idx("android"), idx(ANDROID_NS))

    data, offsets = b"", []
    for text in strings:  # UTF-16: 글자 수(2바이트) + 본문 + 끝 표시(2바이트)
        offsets.append(len(data))
        data += struct.pack("<H", len(text)) + text.encode("utf-16-le") + b"\x00\x00"
    data += b"\x00" * (-len(data) % 4)
    strings_start = 28 + 4 * len(strings)
    pool = (struct.pack("<HHIIIIII", 0x0001, 28, strings_start + len(data), len(strings), 0, 0, strings_start, 0)
            + b"".join(struct.pack("<I", o) for o in offsets) + data)
    res_ids = struct.pack("<HHI", 0x0180, 8, 8 + 4 * len(_ATTR_IDS)) + b"".join(
        struct.pack("<I", i) for i in _ATTR_IDS.values())
    content = pool + res_ids + tree
    return struct.pack("<HHI", 0x0003, 8, 8 + len(content)) + content


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

    # 앱 패키지: 컴파일된 매니페스트를 갖춘 APK, ZIP으로 둔 APK, IPA / 일반 ZIP의 이름만 바꾼 APK
    apps = root / "apps"
    dex = b"dex\n035\x00" + bytes(104)
    make_zip(apps / "structured_sample.apk", {
        "AndroidManifest.xml": android_manifest_bytes(
            "org.example.notes", 7, "1.2.0", 24, 34,
            ["android.permission.INTERNET", "android.permission.READ_CONTACTS"], "Sample Notes"),
        "classes.dex": dex})
    make_zip(apps / "backup.zip", {
        "AndroidManifest.xml": android_manifest_bytes(
            "com.example.tracker", 3, "0.9", 21, 30,
            ["android.permission.ACCESS_FINE_LOCATION", "android.permission.RECEIVE_BOOT_COMPLETED"], "Tracker"),
        "classes.dex": dex})
    info = plistlib.dumps({"CFBundleIdentifier": "org.example.photos", "CFBundleDisplayName": "Photos Sample",
                           "CFBundleShortVersionString": "2.1", "CFBundleVersion": "210", "MinimumOSVersion": "15.0",
                           "DTPlatformVersion": "17.0", "NSCameraUsageDescription": "사진 촬영",
                           "NSPhotoLibraryUsageDescription": "앨범 저장"}, fmt=plistlib.FMT_BINARY)
    make_zip(apps / "sample.ipa", {"Payload/Photos.app/Info.plist": info,
                                   "Payload/Photos.app/_CodeSignature/CodeResources": b"<plist/>"})
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
